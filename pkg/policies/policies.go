package policies

import (
	"bufio"
	"encoding/json"
	"os"
	"time"

	"github.com/cainelli/opa-firewall/pkg/firewall"
	"github.com/cainelli/opa-firewall/pkg/stream"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/sirupsen/logrus"
)

// New ...
func New(policies []PolicyInterface, logger *logrus.Logger) *PolicyController {
	producer, err := stream.NewProducer()
	if err != nil {
		panic(err)
	}
	policyController := &PolicyController{
		Logger:             logger,
		Policies:           policies,
		Producer:           producer,
		syncPolicyInterval: 15 * time.Second, // TODO: make it configurable and fix interval before production
	}

	policyController.syncPolicies()

	go policyController.periodicallySyncPolicies()

	return policyController
}

// Run ...
func (controller *PolicyController) Run() {
	file, err := os.Open("./config/development/events.json")
	if err != nil {
		controller.Logger.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		event := &IngressEvent{}

		err := json.Unmarshal(scanner.Bytes(), event)
		if err != nil {
			controller.Logger.Warning("could not parse json", err)
			continue
		}

		policyEvents := controller.Evaluate(event)
		if len(policyEvents) > 0 {
			for _, policyEvent := range policyEvents {
				err := controller.SendPolicyEvent(policyEvent)
				if err != nil {
					controller.Logger.Error(err)
					continue
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		controller.Logger.Error(err)
	}
}

// Evaluate will call the policies and and return a PolicyEvent .
func (controller *PolicyController) Evaluate(event *IngressEvent) []firewall.PolicyEvent {
	policyEvents := []firewall.PolicyEvent{}
	for _, policy := range controller.Policies {
		isRelevant, err := policy.IsRelevant(event)
		if err != nil {
			controller.Logger.Errorf("%s: %v", policy.Name(), err)
			continue
		}

		if !isRelevant {
			continue
		}

		policyEvent, err := policy.Process(event)
		if err != nil {
			controller.Logger.Errorf("%s: %v", policy.Name(), err)
			continue
		}
		if err != nil {
			controller.Logger.Errorf("%s: %v", policy.Name(), err)
			continue
		}
		// check if policy is empty
		if policyEvent.Name == "" {
			continue
		}

		policyEvents = append(policyEvents, policyEvent)
	}
	return policyEvents
}

// SendPolicyEvent ...
func (controller *PolicyController) SendPolicyEvent(event firewall.PolicyEvent) error {
	deliveryChan := make(chan kafka.Event)
	defer close(deliveryChan)

	policyEventBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	topicName := firewall.PolicyTopicName

	// TODO: cleanup logging
	controller.Logger.Infof("sending event: %s", string(policyEventBytes))

	controller.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topicName},
		Value:          policyEventBytes,
	}, deliveryChan)

	if err == nil {
		event := <-deliveryChan
		message := event.(*kafka.Message)
		err = message.TopicPartition.Error
	}

	return err
}

func (controller *PolicyController) periodicallySyncPolicies() {
	for {
		select {
		case <-time.After(controller.syncPolicyInterval):
			controller.syncPolicies()
		}
	}
}

func (controller *PolicyController) syncPolicies() {
	for _, policy := range controller.Policies {
		policyEvent, err := policy.Get()
		if err != nil {
			controller.Logger.Error(err)
			continue
		}

		if policyEvent.Type != firewall.EventTypeFull {
			controller.Logger.Errorf("expected %s event type for policy %s", firewall.EventTypeFull, policy.Name())
			continue
		}

		if policyEvent.Rego == "" {
			controller.Logger.Errorf("rego policy not found for policy %s", policy.Name())
			continue
		}

		err = controller.SendPolicyEvent(policyEvent)
		if err != nil {
			controller.Logger.Error(err)
			continue
		}
	}
}
