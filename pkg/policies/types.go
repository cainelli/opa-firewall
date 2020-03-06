package policies

import (
	"github.com/cainelli/opa-firewall/pkg/firewall"
	"github.com/sirupsen/logrus"
)

// PolicyController ...
type PolicyController struct {
	Logger          *logrus.Logger
	Policies        []PolicyInterface
	ProcessingEvent *IngressEvent
}

// IngressEvent defines the event struct sent during the request cycle
type IngressEvent struct {
	Host        string              `json:"host,omitempty"`
	Path        string              `json:"path,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	IP          string              `json:"ip,omitempty"`
	Time        string              `json:"time,omitempty"`
	Status      string              `json:"status,omitempty"`
	UserAgent   string              `json:"user-agent,omitempty"`
	EncryptedIP string              `json:"encrypted-ip,omitempty"`
}

// PolicyInterface is the interface that rules needs to implement to be evaluated
type PolicyInterface interface {
	// IsRelevant Returns true if the rule is relevant for this event
	// For example, some rules might only apply for specific virtual hosts,
	// URIs or geoip locations. If IsRelevant returns false, Classify and
	// Process will not be called for this event.
	IsRelevant(event *IngressEvent) (bool, error)
	// Process the request to collect data which will be used to classify the
	// request as legitimate or not. An implementation of this method will
	// typically look at the request and record some data about it in a shared
	// cache
	Process(event *IngressEvent) error
	// Returns a policy event if the request is suspicious and indicates a need to block.
	// An implementation will typically look at the
	// request event, as well as data recorded about the request in shared dicts
	// in order to apply the policy.
	Classify(event *IngressEvent) (firewall.PolicyEvent, error)
	// Name returns the name of the Policy being implemented.
	Name() string
}
