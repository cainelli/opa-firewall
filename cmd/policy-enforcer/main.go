package main

import (
	"log"
	"net/http"

	"github.com/cainelli/opa-firewall/pkg/firewall"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()

	handler := firewall.New(logger)
	http.HandleFunc("/", handler.OnRequest)
	http.HandleFunc("/iptrees", handler.DumpIPTrees)
	http.HandleFunc("/policies", handler.DumpPolicies)

	log.Print("server ready")
	http.ListenAndServe(":8080", nil)
}
