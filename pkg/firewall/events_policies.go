package firewall

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/cainelli/opa-firewall/pkg/stream"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/open-policy-agent/opa/ast"
)

// ConsumePolicies ...
func (firewall *Firewall) consumePoliciesForever() {
	consumer, err := stream.NewConsumer()
	if err != nil {
		panic(err)
	}
	consumer.SubscribeTopics([]string{PolicyTopicName}, nil)

	for {
		start := time.Now()
		firewall.Logger.Info("consuming policy events")

		msg, err := consumer.ReadMessage(-1)

		if err == nil {
			policyEvent, err := unmarshalPolicyEvent(msg)
			if err != nil {
				firewall.Logger.Error(err)
				return
			}
			firewall.Logger.Infof("policy event %s type %s", policyEvent.Name, policyEvent.Type)

			switch policyEvent.Type {
			case EventTypeFull:
				if err := isValidPolicy(policyEvent, EventTypeFull); err != nil {
					firewall.Logger.Error(err)
					return
				}
				// TODO: mutex to avoid race conditions
				firewall.Policies[policyEvent.Name] = *policyEvent
			case EventTypePatch:
				if err := isValidPolicy(policyEvent, EventTypePatch); err != nil {
					firewall.Logger.Error(err)
					return
				}

				// TODO: patch store if data policy.Data changes
				if _, ok := firewall.Policies[policyEvent.Name]; !ok {
					firewall.Logger.Infof("(skipping) no policy found for patch of %s", policyEvent.Name)
					return
				}
				// updates iptree
				for bucketName, bucket := range policyEvent.IPBuckets {
					ipTree := firewall.getIPTreeOrNew(policyEvent.Name, bucketName)

					for ipString, expireAt := range bucket {
						ip := net.ParseIP(ipString)
						if time.Now().After(expireAt) {
							firewall.Logger.Infof("(expired entry) ip %s to iptree[%s][%s] expiring at: %v", ip, policyEvent.Name, bucketName, expireAt)
							continue
						}

						// TODO: safe add this entry
						firewall.Policies[policyEvent.Name].IPBuckets[bucketName][ipString] = expireAt

						firewall.Logger.Infof("(patching) adding ip %s to iptree[%s][%s] expiring at: %v", ip, policyEvent.Name, bucketName, expireAt)
						err := ipTree.AddIP(ip, expireAt)
						if err != nil {
							firewall.Logger.Error(err)
							continue
						}
					}
				}
			default:
				firewall.Logger.Errorf("%s event type not implemented", policyEvent.Type)
			}
		} else {
			firewall.Logger.Error(err)
		}

		lag, err := consumerLag(consumer)
		if err != nil {
			firewall.Logger.Error(err)
			continue
		}
		firewall.PoliciesBacklog = lag
		firewall.startedConsuming = true

		firewall.Logger.Infof("finished consuming policies (current lag %d) (took %s)", lag, time.Since(start))
	}

}

func unmarshalPolicyEvent(event *kafka.Message) (*PolicyEvent, error) {
	policyEvent := &PolicyEvent{}
	err := json.Unmarshal(event.Value, policyEvent)

	return policyEvent, err
}

// testRego validates if the rego string from event is valid
// TODO: fix custom built in function errors
func testRego(rego string) error {
	_, err := ast.CompileModules(map[string]string{"firewall": rego})

	return err
}

func isValidPolicy(policyEvent *PolicyEvent, policyType string) error {
	if policyEvent.Name == "" {
		return fmt.Errorf("missing policy name")
	}

	if policyEvent.Type == "" {
		return fmt.Errorf("missing event type for policy %s", policyEvent.Name)
	}

	switch policyType {
	case EventTypeFull:
		if policyEvent.Rego == "" {
			return fmt.Errorf("rego is missing for policy %s", policyEvent.Name)
		}

	case EventTypePatch:
		if policyEvent.Data == nil && policyEvent.IPBuckets == nil {
			return fmt.Errorf("data or ipbuckets missing for policy %s", policyEvent.Name)
		}
	default:
		return fmt.Errorf("unknown policy type %s", policyType)
	}

	return nil
}

// consumerLag returns the combined total of "lag" all toppar's have that this
// consumer consumes from. For example, if this consumer is consuming from
// topic "foo" and is assigned to partitions 0, 2, and 3, then the backlog will
// be the log-end offset, minus the current offset, for all three partitions,
// added together.
// https://github.com/confluentinc/confluent-kafka-go/issues/201
func consumerLag(consumer *kafka.Consumer) (int, error) {
	var n int

	// Get the current assigned partitions.
	toppars, err := consumer.Assignment()
	if err != nil {
		return n, err
	}

	// Get the current offset for each partition, assigned to this consumer group.
	toppars, err = consumer.Committed(toppars, 5000)
	if err != nil {
		return n, err
	}

	// Loop over the topic partitions, get the high watermark for each toppar, and
	// subtract the current offset from that number, to get the total "lag". We
	// combine this value for each toppar to get the final backlog integer.
	var l, h int64
	for i := range toppars {
		l, h, err = consumer.QueryWatermarkOffsets(*toppars[i].Topic, toppars[i].Partition, 5000)
		if err != nil {
			return n, err
		}

		o := int64(toppars[i].Offset)
		if toppars[i].Offset == kafka.OffsetInvalid {
			o = l
		}

		n = n + int(h-o)
	}

	return n, nil
}
