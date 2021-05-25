package webhooks

import (
	kyvernov1alpha1 "github.com/kyverno/kyverno/pkg/api/kyverno/v1alpha1"
	"github.com/kyverno/kyverno/pkg/common"
	"strings"

	"github.com/go-logr/logr"
	"github.com/kyverno/kyverno/pkg/engine/response"

	"github.com/kyverno/kyverno/pkg/event"
)

//generateEvents generates event info for the engine responses
func generateEvents(engineResponses []*response.EngineResponse, blocked, onUpdate, successEvents bool, log logr.Logger) []event.Info {
	var events []event.Info

	// Scenario 1
	// - Admission-Response is SUCCESS && CREATE
	//   - All policies were successful
	//     - report event on resources
	if successEvents && isResponseSuccessful(engineResponses) {
		if !onUpdate {
			// we only report events on CREATE requests
			return events
		}
		for _, er := range engineResponses {
			// event on resource
			eResource := event.NewEvent(
				log,
				er.PolicyResponse.Resource.Kind,
				er.PolicyResponse.Resource.APIVersion,
				er.PolicyResponse.Resource.Namespace,
				er.PolicyResponse.Resource.Name,
				event.PolicyApplied.String(),
				event.AdmissionController,
				event.SResourcePolicyApply,
				er.PolicyResponse.Policy,
			)
			// event on policy
			ePolicy := event.NewEvent(
				log,
				"ClusterPolicy",
				kyvernov1alpha1.SchemeGroupVersion.String(),
				"",
				er.PolicyResponse.Policy,
				event.PolicyApplied.String(),
				event.AdmissionController,
				event.SPolicyApply,
				er.PolicyResponse.Resource.GetKey(),
			)
			events = append(events, eResource, ePolicy)
		}
		return events
	}

	// Scneario 2
	// - Admission-Response is BLOCKED
	//   - report event of policy is in enforce mode and failed to apply
	if blocked {
		for _, er := range engineResponses {
			if er.IsSuccessful() {
				// do not create event on polices that were succesfuly
				continue
			}
			if er.PolicyResponse.ValidationFailureAction != common.Enforce {
				// do not create event on "audit" policy
				continue
			}
			// Rules that failed
			failedRules := er.GetFailedRules()
			filedRulesStr := strings.Join(failedRules, ";")
			// Event on Policy
			e := event.NewEvent(
				log,
				"ClusterPolicy",
				kyvernov1alpha1.SchemeGroupVersion.String(),
				"",
				er.PolicyResponse.Policy,
				event.RequestBlocked.String(),
				event.AdmissionController,
				event.FPolicyBlockResourceUpdate,
				er.PolicyResponse.Resource.GetKey(),
				filedRulesStr,
			)
			events = append(events, e)
		}
		return events
	}

	// Scenario 3
	// - Admission-Response is SUCCESS
	//   - Some/All policies failed (policy violations generated)
	//     - report event on policy that failed
	//     - report event on resource that failed
	for _, er := range engineResponses {
		if er.IsSuccessful() {
			// do not create event on rules that were successful
			continue
		}
		// Rules that failed
		failedRules := er.GetFailedRules()
		filedRulesStr := strings.Join(failedRules, ";")

		// Event on the policy
		ePolicy := event.NewEvent(
			log,
			"ClusterPolicy",
			kyvernov1alpha1.SchemeGroupVersion.String(),
			"",
			er.PolicyResponse.Policy,
			event.PolicyFailed.String(),
			event.AdmissionController,
			event.FPolicyApplyFailed,
			filedRulesStr,
			er.PolicyResponse.Resource.GetKey(),
		)
		// Event on the resource
		eResource := event.NewEvent(
			log,
			er.PolicyResponse.Resource.Kind,
			er.PolicyResponse.Resource.APIVersion,
			er.PolicyResponse.Resource.Namespace,
			er.PolicyResponse.Resource.Name,
			event.PolicyViolation.String(),
			event.AdmissionController,
			event.FResourcePolicyFailed,
			filedRulesStr,
			er.PolicyResponse.Policy,
		)
		events = append(events, ePolicy, eResource)
	}

	return events
}
