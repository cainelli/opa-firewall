package firewall

import (
	"net"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

// RegisterCustomBultin ...
func (firewall *Firewall) registerCustomBultin() func(r *rego.Rego) {
	return rego.Function3(
		&rego.Function{
			Name: "in_tree",
			Decl: types.NewFunction(types.Args(types.S, types.S, types.S), types.B),
		}, firewall.builtinInTree,
	)
}

func (firewall *Firewall) builtinInTree(_ rego.BuiltinContext, policyName, treeName, ip *ast.Term) (*ast.Term, error) {
	firewall.Logger.Info("built_in_tree called")
	if _, ok := policyName.Value.(ast.String); !ok {
		return nil, nil
	}
	if _, ok := treeName.Value.(ast.String); !ok {
		return nil, nil
	}

	if _, ok := ip.Value.(ast.String); !ok {
		return nil, nil
	}

	ipString := string(ip.Value.(ast.String))
	policyNameString := string(policyName.Value.(ast.String))
	treeNameString := string(treeName.Value.(ast.String))

	if _, ok := firewall.IPTrees[policyNameString]; !ok {
		firewall.Logger.Infof("couldn't find ip tree for policy %s", policyNameString)
		return nil, nil
	}

	if _, ok := firewall.IPTrees[policyNameString][treeNameString]; !ok {
		firewall.Logger.Infof("couldn't find ip tree for policy %s and bucket %s", policyNameString, treeNameString)
		return nil, nil
	}

	ipTree := firewall.IPTrees[policyNameString][treeNameString]
	if expireAt, exist := ipTree.GetIP(net.ParseIP(ipString)); exist {
		if time.Now().After(expireAt) {
			firewall.Logger.Infof("policy %s lookup ip %s in tree %s is true but expired", policyNameString, ipString, treeNameString)
			return nil, nil
		}
		firewall.Logger.Infof("ip %s is blacklisted by policy %s and bucket %s", ipString, policyNameString, treeNameString)
		return ast.BooleanTerm(true), nil
	}

	return nil, nil
}
