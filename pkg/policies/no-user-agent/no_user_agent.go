package nouseragent

import (
	"strings"

	"github.com/cainelli/opa-firewall/pkg/firewall"
	"github.com/cainelli/opa-firewall/pkg/policies"
	"github.com/sirupsen/logrus"
)

// Policy implements the policy.PolicyInterface and is the global policy for requests with no user agent present
type Policy struct {
	Logger *logrus.Logger
}

// New initializes the policy
func New(logger *logrus.Logger) policies.PolicyInterface {
	return &Policy{
		Logger: logger,
	}
}

// IsRelevant returns true for events relevant for this policy
func (policy *Policy) IsRelevant(event *policies.IngressEvent) (bool, error) {
	switch {
	case strings.HasPrefix(event.Host, "www."):
		return true, nil
	case strings.HasPrefix(event.Host, "activities."):
		return true, nil
	default:
		return false, nil
	}
}

// Process increments counters to the policy bucket
func (policy *Policy) Process(event *policies.IngressEvent) error {
	if event.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               == "" {
		policy.Logger.Info("oops")
		return nil
	}

	return nil
}

// Classify returns a PolicyEvent to be sent to the firewall if the request is suspecious
func (policy *Policy) Classify(event *policies.IngressEvent) (firewall.PolicyEvent, error) {
	return firewall.PolicyEvent{
		Name: policy.Name(),
	}, nil
}

// Name of the policy implemented
func (policy *Policy) Name() string {
	return "No User-Agent"
}
