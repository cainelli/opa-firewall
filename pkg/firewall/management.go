package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cainelli/opa-firewall/pkg/iptree"
)

//DumpIPTrees ...
func (firewall *Firewall) DumpIPTrees(writer http.ResponseWriter, request *http.Request) {

	res := make(map[string]map[string]iptree.FlatJSON)

	for policyName, buckets := range firewall.IPTrees {
		res[policyName] = map[string]iptree.FlatJSON{}
		for bucketName, tree := range buckets {
			treeFormatted, err := tree.ToFlatJSON()
			if err != nil {
				firewall.Logger.Error(err)
				continue
			}
			res[policyName][bucketName] = treeFormatted
		}
	}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		firewall.Logger.Error(err)
		return
	}

	fmt.Fprintf(writer, string(jsonBytes))
}

// DumpPolicies ..
func (firewall *Firewall) DumpPolicies(writer http.ResponseWriter, request *http.Request) {
	jsonBytes, err := json.Marshal(firewall.Policies)
	if err != nil {
		firewall.Logger.Error(err)
		return
	}

	fmt.Fprintf(writer, string(jsonBytes))
}
