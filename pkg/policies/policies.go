package policies

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/cainelli/opa-firewall/pkg/firewall"
	"github.com/sirupsen/logrus"
)

// New ...
func New(policies []PolicyInterface, logger *logrus.Logger) *PolicyController {
	return &PolicyController{
		Logger:   logger,
		Policies: policies,
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

		controller.ProcessingEvent = event

		policyEvents := controller.Evaluate()
		if len(policyEvents) > 0 {
			for _, policyEvent := range policyEvents {
				controller.Logger.Info(policyEvent.Name)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		controller.Logger.Error(err)
	}
}

// Evaluate will call the policies and and return a PolicyEvent from Classify functions.
func (controller *PolicyController) Evaluate() []firewall.PolicyEvent {
	policyEvents := []firewall.PolicyEvent{}
	for _, policy := range controller.Policies {
		isRelevant, err := policy.IsRelevant(controller.ProcessingEvent)
		if err != nil {
			controller.Logger.Errorf("%s: %v", policy.Name(), err)
			continue
		}

		if !isRelevant {
			continue
		}

		err = policy.Process(controller.ProcessingEvent)
		if err != nil {
			controller.Logger.Errorf("%s: %v", policy.Name(), err)
			continue
		}

		policyEvent, err := policy.Classify(controller.ProcessingEvent)
		if err != nil {
			controller.Logger.Errorf("%s: %v", policy.Name(), err)
			continue
		}
		if policyEvent != (firewall.PolicyEvent{}) {
			policyEvents = append(policyEvents, policyEvent)
		}
	}
	return policyEvents
}
