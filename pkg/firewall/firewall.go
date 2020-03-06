package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// GetStaticPolicies ...
func GetStaticPolicies() ([]*PolicyEvent, error) {
	policyPath := "./policies"
	files, err := ioutil.ReadDir(policyPath)
	if err != nil {
		return []*PolicyEvent{}, err
	}

	policies := []*PolicyEvent{}
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
		policies = append(policies, policyEvent)
	}
	return policies, nil
}

// TestRego validates if the rego string from event is valid
func TestRego(rego string) error {
	combined := fmt.Sprintf("package firewall\n%s", rego)
	_, err := ast.CompileModules(map[string]string{"firewall": combined})

	return err
}

// CompilePolicies ...
func CompilePolicies(policies []*PolicyEvent) (*ast.Compiler, storage.Store) {
	stores := make(map[string]interface{})
	combinedRego := "package firewall"

	for _, policy := range policies {
		// test module before adding it to the map.
		if err := TestRego(policy.Rego); err != nil {
			log.Printf("could not parse rego of %s: %s", policy.Name, err)
		}
		combinedRego = fmt.Sprintf("%s\n%s", combinedRego, policy.Rego)

		// test if data is json compatible.
		_, err := json.Marshal(policy.Data)
		if err != nil {
			log.Fatal(err)
		} else if policy.Data != nil {
			stores[policy.Name] = policy.Data
		}
	}

	compiledModules, err := ast.CompileModules(map[string]string{"firewall": combinedRego})
	if err != nil {
		log.Fatal(err)
	}

	dataJSON, err := json.Marshal(stores)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("data:%v", string(dataJSON))
	store := inmem.NewFromReader(bytes.NewBuffer(dataJSON))

	return compiledModules, store
}

// New initialized the firewall handler
func New() *Firewall {
	policies, err := GetStaticPolicies()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%v policies\n", len(policies))
	compilers, store := CompilePolicies(policies)
	return &Firewall{
		Compilers: compilers,
		Store:     store,
	}
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
						log.Printf("%s data type (%v) not supported: %v", moduleName, reflect.TypeOf(data), InterfaceToString(data))
					}
				}
			default:
				log.Printf("expression value type (%v) not supported: %v", reflect.TypeOf(result), InterfaceToString(result))
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

// InterfaceToString ...
func InterfaceToString(i interface{}) string {
	bytes, err := json.Marshal(i)
	if err != nil {
		log.Printf("could not marshal interface %v", i)
	}
	return string(bytes)

}
