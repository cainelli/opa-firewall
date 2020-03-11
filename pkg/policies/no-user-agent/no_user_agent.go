package nouseragent

import (
	"strings"
	"time"

	"github.com/cainelli/opa-firewall/pkg/firewall"
	"github.com/cainelli/opa-firewall/pkg/iptree"
	"github.com/cainelli/opa-firewall/pkg/policies"
	"github.com/cainelli/opa-firewall/pkg/ratelimiter"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// Policy implements the policy.PolicyInterface and is the global policy for requests with no user agent present
type Policy struct {
	policies.Policy

	IPBuckets iptree.IPBuckets
	Cache     *cache.Cache
	Data      *PolicyData
}

const (
	// BlackListIPBucketName ...
	BlackListIPBucketName = "blacklist"
)

// PolicyData ..
type PolicyData struct {
}

// New initializes the policy
func New(logger *logrus.Logger) policies.PolicyInterface {
	policy := &Policy{
		Cache: cache.New(5*time.Minute, 5*time.Minute),
	}

	rateLimiter := ratelimiter.NewRateLimiter(rate.Every(time.Second*2), 1)

	policy.RateLimiter = rateLimiter
	policy.Logger = logger

	policy.BlockDuration = 24 * time.Hour

	return policy
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
func (policy *Policy) Process(event *policies.IngressEvent) (firewall.PolicyEvent, error) {
	eventTime, err := policy.ConvertEventTime(event.Time)
	if err != nil {
		return firewall.PolicyEvent{}, err
	}

	// Do not process the rule if the event date/time is too old.
	// TODO: move this to the interface caller if possible as it is common between all policies
	if time.Now().After(eventTime.Add(policy.BlockDuration)) {
		policy.Logger.Debug("event is too old (%s) to be processed", eventTime)
		return firewall.PolicyEvent{}, nil
	}

	allowed, err := policy.RateLimiter.IsAllowed(event.IP, eventTime)
	if err != nil {
		return firewall.PolicyEvent{}, err
	}

	if !allowed {
		// skip if policy was already returned for this IP but keeps falling into rate limit.
		// TODO: maybe rate limiter provides something in these lines.
		if _, ok := policy.Cache.Get(event.IP); !ok {
			policy.Cache.Set(event.IP, true, policy.BlockDuration)

			return firewall.PolicyEvent{
				Name: policy.Name(),
				Type: firewall.EventTypePatch,
				IPBuckets: firewall.IPBuckets{
					BlackListIPBucketName: {
						event.IP: time.Now().Add(policy.BlockDuration),
					},
				},
			}, nil
		}
	}

	return firewall.PolicyEvent{}, nil

}

// GetPolicyEvent returns a PolicyEvent to be sent to the firewall if the request is suspecious
func (policy *Policy) GetPolicyEvent(event *policies.IngressEvent) (firewall.PolicyEvent, error) {
	return firewall.PolicyEvent{
		Name: policy.Name(),
		Type: firewall.EventTypeFull,
		Rego: `
deny {
	startswith(input.host, www.)
	ip_in_tree(input.ip, blacklist)
}

deny {
	startswith(input.host, activities.)
	ip_in_tree(input.ip, blacklist)
}
`,
	}, nil
}

// Name of the policy implemented
func (policy *Policy) Name() string {
	return "nouseragent"
}
