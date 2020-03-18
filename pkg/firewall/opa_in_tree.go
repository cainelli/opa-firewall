package firewall

import (
	"fmt"

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
	if _, ok := policyName.Value.(ast.String); !ok {
		return ast.BooleanTerm(false), nil
	}
	if _, ok := treeName.Value.(ast.String); !ok {
		return ast.BooleanTerm(false), nil
	}

	if _, ok := ip.Value.(ast.String); !ok {
		return ast.BooleanTerm(false), nil
	}

	firewall.Logger.Infof("policy %s lookup ip %s in tree %s", policyName.String(), ip.String(), treeName.String())
	fmt.Print(ip.String())
	if ip.String() == `"1.1.1.1"` {
		firewall.Logger.Error("returning true in lookup")
		return ast.BooleanTerm(true), nil
	}
	return nil, nil
}
