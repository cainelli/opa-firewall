package firewall

import (
	"encoding/json"
	"fmt"

	"github.com/cainelli/opa-firewall/pkg/stream"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/open-policy-agent/opa/ast"
)

// ConsumePolicies ...
func (firewall *Firewall) ConsumePolicies() {
	consumer, err := stream.NewConsumer()
	if err != nil {
		panic(err)
	}
	consumer.SubscribeTopics([]string{PolicyTopicName}, nil)

	for {
		msg, err := consumer.ReadMessage(-1)
		if err == nil {
			policyEvent, err := unmarshalPolicyEvent(msg)
			if err != nil {
				firewall.Logger.Error(err)
				continue
			}

			switch policyEvent.Type {
			case EventTypeFull:
				if err := isValidPolicy(policyEvent, EventTypeFull); err != nil {
					firewall.Logger.Error(err)
					continue
				}
				// TODO: mutex to avoid race conditions
				firewall.Policies[policyEvent.Name] = *policyEvent
			case EventTypePatch:
				if err := isValidPolicy(policyEvent, EventTypePatch); err != nil {
					firewall.Logger.Error(err)
					continue
				}
				// TODO: patch store if data policy.Data changes
				// TODO: patch ip data tree if policy.IPBuckets change
				firewall.Logger.Errorf("%s event type not implemented", policyEvent.Type)
			default:
				firewall.Logger.Errorf("%s event type not implemented", policyEvent.Type)
			}
		} else {
			firewall.Logger.Error(err)
		}
	}

	consumer.Close()
}

func unmarshalPolicyEvent(event *kafka.Message) (*PolicyEvent, error) {
	policyEvent := &PolicyEvent{}
	err := json.Unmarshal(event.Value, policyEvent)

	return policyEvent, err
}

// testRego validates if the rego string from event is valid
func testRego(rego string) error {
	combined := fmt.Sprintf("package firewall\n%s", rego)
	_, err := ast.CompileModules(map[string]string{"firewall": combined})

	return err
}

func isValidPolicy(policyEvent *PolicyEvent, policyType string) error {
	if policyEvent.Name == "" {
		return fmt.Errorf("missing policy name")
	}

	if policyEvent.Type == "" {
		return fmt.Errorf("missing event type for policy", policyEvent.Name)
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
