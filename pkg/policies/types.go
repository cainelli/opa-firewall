package policies

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cainelli/opa-firewall/pkg/firewall"
	"github.com/cainelli/opa-firewall/pkg/ratelimiter"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

// PolicyController ...
type PolicyController struct {
	Logger             *logrus.Logger
	Policies           []PolicyInterface
	Producer           *kafka.Producer
	syncPolicyInterval time.Duration
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
	// URIs or geoip locations. If IsRelevant returns false
	// Process will not be called for this event.
	IsRelevant(event *IngressEvent) (bool, error)
	// Process the request to collect data which will be used to classify the
	// request as legitimate or not. An implementation of this method will
	// typically look at the request and record some data about it in a shared
	// cache
	Process(event *IngressEvent) (firewall.PolicyEvent, error)
	// Get returns a policy event containing the full data.
	Get() (firewall.PolicyEvent, error)
	// Name returns the name of the Policy being implemented.
	Name() string
}

// Policy ...
type Policy struct {
	RateLimiter   *ratelimiter.RateLimiter
	Logger        *logrus.Logger
	BlockDuration time.Duration
}

// ConvertEventTime takes an event time string and converts it to time.Time
func (policy *Policy) ConvertEventTime(timeString string) (time.Time, error) {
	timeSplitted := strings.Split(timeString, ".")
	if len(timeSplitted) != 2 {
		return time.Time{}, fmt.Errorf("wrong time format:%s, expected something like 1583503992.449", timeString)
	}

	unixTimeStamp, err := strconv.ParseInt(timeSplitted[0], 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	miliseconds, err := strconv.ParseInt(timeSplitted[1], 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	nanoseconds := miliseconds * 1000000

	return time.Unix(unixTimeStamp, nanoseconds), nil

}

// GetIPBucketFromCache ...
func (policy *Policy) GetIPBucketFromCache(cache *cache.Cache) firewall.IPBucket {
	ipBucket := make(firewall.IPBucket)
	for ip, item := range cache.Items() {
		ipBucket[ip] = time.Unix(0, item.Expiration)
	}
	return ipBucket
}
