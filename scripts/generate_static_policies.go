package main

import (
	"fmt"
	"os"
	"text/template"

	"github.com/Pallinder/go-randomdata"
)

func main() {

	type Policy struct {
		Name   string
		Count  int
		NIps   []int
		NRules []int
		IPList string
	}

	nFiles := 1
	nRules := 5000
	nIPs := 0
	OPAPackage := &Policy{Name: "supplier", Count: 1}

	rawTemplate := `
---
{{- $name := .Name }}
{{- $count := .Count}}
{{- $ipList := .IPList}}
name: {{$name}}{{$count}}
type: full
rego: |
  package firewall

  {{- range $index := .NRules  }}
  deny {
    input.host = "{{$name}}{{.}}.domain.com"
    input.path = "/login-{{.}}"
    input.ip = "1.1.1.{{.}}"}
{{- end}}
data:
  blacklist: {{$ipList}}`

	for i := 0; i < nRules; i++ {
		OPAPackage.NRules = append(OPAPackage.NRules, i)
		OPAPackage.NIps = append(OPAPackage.NIps, i)
	}
	for i := 0; i < nFiles; i++ {
		OPAPackage.Count = i
		OPAPackage.IPList = "["

		for ii := 0; ii < nIPs; ii++ {
			if ii == 0 {
				OPAPackage.IPList = OPAPackage.IPList + "\"" + randomdata.IpV4Address() + "\""
			} else {
				OPAPackage.IPList = OPAPackage.IPList + ",\"" + randomdata.IpV4Address() + "\""
			}

		}
		OPAPackage.IPList = OPAPackage.IPList + "]"

		tmpl, err := template.New("policy").Parse(rawTemplate)
		if err != nil {
			panic(err)
		}

		w, err := os.Create(fmt.Sprintf("policies/policy-%d.yml", i))
		if err != nil {
			fmt.Printf("could not create file %v", err)
		}
		err = tmpl.Execute(w, OPAPackage)
		if err != nil {
			panic(err)
		}
	}

}
