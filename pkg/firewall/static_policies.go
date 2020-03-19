package firewall

import (
	"fmt"
	"io/ioutil"

	"github.com/ghodss/yaml"
)

// GetStaticPolicies ...
func GetStaticPolicies() (map[string]PolicyEvent, error) {
	policies := make(map[string]PolicyEvent)
	policyPath := "./policies"
	files, err := ioutil.ReadDir(policyPath)
	if err != nil {
		return policies, err
	}

	for _, file := range files {
		policyEvent := &PolicyEvent{}
		policyBytes, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", policyPath, file.Name()))
		if err != nil {
			fmt.Printf("could not open file %s: %v", file.Name(), err)
			continue
		}
		err = yaml.Unmarshal(policyBytes, policyEvent)
		if err != nil {
			fmt.Printf("error unmarshaling policy %s", file.Name())
			continue
		}

		err = isValidPolicy(policyEvent, EventTypeFull)
		if err != nil {
			fmt.Print(err)
			continue
		}

		policies[policyEvent.Name] = *policyEvent
	}
	return policies, nil
}
