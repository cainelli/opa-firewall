package policies

import (
	"bufio"
	"encoding/json"
	"os"

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
	return &PolicyController{
		Logger:          logger,
		Policies:        policies,
		Producer:        producer,
		EventsTopicName: "firewall-events",
		PolicyTopicName: "firewall-policies",
	}
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

	controller.Logger.Infof("producing policy event to %s", controller.PolicyTopicName)
	controller.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &controller.PolicyTopicName},
		Value:          policyEventBytes,
	}, deliveryChan)

	if err == nil {
		event := <-deliveryChan
		message := event.(*kafka.Message)
		err = message.TopicPartition.Error
	}

	return err
}
