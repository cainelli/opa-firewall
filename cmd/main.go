package main

import (
	"log"
	"net/http"

	"github.com/cainelli/opa-firewall/internal/pkg/firewall"
)

func main() {

	log.Print("running server")

	handler := firewall.New()
	http.HandleFunc("/", handler.OnRequest)

	http.ListenAndServe(":8080", nil)

}
