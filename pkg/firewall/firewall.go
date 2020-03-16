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
	}

	compilers, store, ipTrees := firewall.CompilePolicies(policies)
	firewall.Compilers = compilers
	firewall.Store = store
	firewall.IPTrees = ipTrees

	go firewall.ConsumePolicies()
	go firewall.periodicallyCompilePolicies()

	return firewall
}

// OnRequest handler for firewall functionality
func (firewall *Firewall) OnRequest(writer http.ResponseWriter, request *http.Request) {
	status := http.StatusOK

	normalizedHeaders := make(map[string][]string)
	for header, values := range request.Header {
		normalizedHeaders[strings.ToLower(header)] = values
	}

	firewall.Input = map[string]interface{}{
		"host":    request.Host,
		"method":  request.Method,
		"path":    request.URL.Path,
		"headers": normalizedHeaders,
		"ip":      request.Header.Get("x-forwarded-for"),
	}

	allow, err := firewall.Evaluate()
	if err != nil {
		log.Print(err)
	}
	if !allow {
		status = http.StatusTooManyRequests
	}

	writer.WriteHeader(status)

	_, _ = fmt.Fprintln(writer, firewall.Input)
	_, _ = fmt.Fprintln(writer, fmt.Sprintf("response:%d", status))
}

// Evaluate ...
func (firewall *Firewall) Evaluate() (bool, error) {
	ctx := context.Background()
	start := time.Now()

	rego := rego.New(
		rego.Query(fmt.Sprintf("data")),
		rego.Compiler(firewall.Compilers),
		rego.Input(firewall.Input),
		rego.Store(firewall.Store),
	)

	// Run evaluation.
	resultSet, err := rego.Eval(ctx)
	if err != nil {
		log.Print("err:", err)
	}

	elapsed := time.Since(start)
	log.Printf("after eval %s", elapsed)

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
