package main

import (
	"log"

	"github.com/cainelli/opa-firewall/pkg/policies"
	nouseragent "github.com/cainelli/opa-firewall/pkg/policies/no-user-agent"
	"github.com/sirupsen/logrus"
)

func main() {

	log.Print("initializing server")

	logger := logrus.New()

	policyController := policies.New([]policies.PolicyInterface{
		nouseragent.New(logger),
	}, logger)

	policyController.Run()

	// handler := firewall.New()
	// http.HandleFunc("/", handler.OnRequest)

	// log.Print("server ready")
	// http.ListenAndServe(":8080", nil)

}
