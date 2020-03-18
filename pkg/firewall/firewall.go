package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
)

// New initialized the firewall handler
func New(logger *logrus.Logger) *Firewall {
	policies, err := GetStaticPolicies()
	if err != nil {
		fmt.Println(err)
	}

	firewall := &Firewall{
		Logger:          logger,
		Policies:        policies,
		CompileInterval: 5 * time.Second, // TODO: make it configurable and fix interval before production
		context:         context.Background(),
	}

	firewall.Compile()

	go firewall.ConsumePolicies()
	go firewall.periodicallyCompile()

	return firewall
}

// OnRequest handler for firewall functionality
func (firewall *Firewall) OnRequest(writer http.ResponseWriter, request *http.Request) {
	status := http.StatusOK

	normalizedHeaders := make(map[string][]string)
	for header, values := range request.Header {
		normalizedHeaders[strings.ToLower(header)] = values
	}

	input := map[string]interface{}{
		"host":    request.Host,
		"method":  request.Method,
		"path":    request.URL.Path,
		"headers": normalizedHeaders,
		"ip":      request.Header.Get("x-forwarded-for"),
	}

	allow, err := firewall.Evaluate(input)
	if err != nil {
		firewall.Logger.Error(err)
	}
	if !allow {
		status = http.StatusTooManyRequests
	}

	writer.WriteHeader(status)

	_, _ = fmt.Fprintln(writer, input)
	_, _ = fmt.Fprintln(writer, fmt.Sprintf("response:%d", status))
}

// Evaluate ...
func (firewall *Firewall) Evaluate(input string) (bool, error) {
	start := time.Now()

	// Run evaluation.
	resultSet, err := firewall.PreparedEval.Eval(firewall.context, rego.EvalInput(input))
	if err != nil {
		firewall.Logger.Error(err)
	}

	elapsed := time.Since(start)
	firewall.Logger.Infof("after eval %s", elapsed)

	// Inspect results.
	fmt.Println("len:", len(resultSet))
	if len(resultSet) > 0 {
		// Do something with result.
		fmt.Println("value:", resultSet[0].Bindings)

		fmt.Println("value:", resultSet[0].Expressions[0])
	}

	// no result allows traffic
	if len(resultSet) == 0 {
		return true, nil
	}

	// Semantics: Lookup for allow and deny expressions to assing them to allow/deny variables.
	// If allow=true we will honour this decision even if deny=true and move to the next module
	var allow, deny bool

	for _, set := range resultSet {
		for _, expression := range set.Expressions {
			switch result := expression.Value.(type) {
			case map[string]interface{}:
				for moduleName, dataInterface := range result {
					switch data := dataInterface.(type) {
					case map[string]interface{}:
						if found, ok := data["allow"]; ok {
							switch value := found.(type) {
							case bool:
								allow = value
							default:
								log.Printf("%s result type (%v) not supported for %v", moduleName, reflect.TypeOf(value), value)
							}
						}

						if found, ok := data["deny"]; ok {
							switch value := found.(type) {
							case bool:
								deny = value
							default:
								log.Printf("%s result type (%v) not supported for %v", moduleName, reflect.TypeOf(value), value)
							}
						}
					default:
						log.Printf("%s data type (%v) not supported: %v", moduleName, reflect.TypeOf(data), interfaceToString(data))
					}
				}
			default:
				log.Printf("expression value type (%v) not supported: %v", reflect.TypeOf(result), interfaceToString(result))
			}
		}
	}

	elapsed = time.Since(start)
	log.Printf("total took %s", elapsed)

	if deny == true && allow == false {
		return false, nil
	}

	// no deny rule allows traffic
	return true, nil
}

// interfaceToString ...
func interfaceToString(i interface{}) string {
	bytes, err := json.Marshal(i)
	if err != nil {
		log.Printf("could not marshal interface %v", i)
	}
	return string(bytes)

}
