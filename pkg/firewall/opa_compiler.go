package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cainelli/opa-firewall/pkg/iptree"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

func (firewall *Firewall) periodicallyCompilePolicies() {
	for {
		select {
		case <-time.After(10 * time.Second):
			firewall.Logger.Info("recompiling rules")
			compilers, store, ipTrees := firewall.CompilePolicies(firewall.Policies)
			firewall.Store = store
			firewall.Compilers = compilers
			firewall.IPTrees = ipTrees
		}
	}
}

// CompilePolicies ...
// TODO:
//   * run periodically CompileInterval
//   * build IP tree
//   * gracefully handle errors
func (firewall *Firewall) CompilePolicies(policies map[string]PolicyEvent) (*ast.Compiler, storage.Store, IPTrees) {
	stores := make(map[string]interface{})
	ipTrees := make(IPTrees)
	combinedRego := "package firewall"

	// TODO: implement mutex to avoid race conditions
	for _, policy := range policies {
		// test module before adding it to the map.
		if err := testRego(policy.Rego); err != nil {
			log.Printf("could not parse rego of %s (skipping): %s ", policy.Name, err)
			continue
		}

		// test if data is json compatible.
		_, err := json.Marshal(policy.Data)
		if err != nil {
			// log error
			continue
		} else if policy.Data != nil {
			stores[policy.Name] = policy.Data
		}

		if policy.IPBuckets != nil {
			for bucketName, bucket := range policy.IPBuckets {
				ipTree := iptree.New()
				for ipString, expireAt := range bucket {
					ip := net.ParseIP(ipString)
					err := ipTree.AddIP(ip, expireAt)
					if err != nil {
						firewall.Logger.Error(err)
						continue
					}

					firewall.Logger.Infof("bucket: %s ip: %v, expireAt: %v", bucketName, ip, expireAt)
				}
			}

		}
		combinedRego = fmt.Sprintf("%s\n%s", combinedRego, policy.Rego)
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

	return compiledModules, store, ipTrees
}
