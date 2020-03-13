package main

import (
	"fmt"

	"github.com/cainelli/opa-firewall/pkg/firewall"
	"github.com/cainelli/opa-firewall/pkg/stream"
)

func main() {
	ConsumePolicies()
	// handler := firewall.New()
	// http.HandleFunc("/", handler.OnRequest)

	// log.Print("server ready")
	// http.ListenAndServe(":8080", nil)
}

// ConsumePolicies ...
func ConsumePolicies() {
	consumer, err := stream.NewConsumer()
	if err != nil {
		panic(err)
	}
	consumer.SubscribeTopics([]string{firewall.PolicyTopicName}, nil)

	for {
		msg, err := consumer.ReadMessage(-1)
		if err == nil {
			fmt.Printf("Message on %s: %s\n", msg.TopicPartition, string(msg.Value))
		} else {
			// The client will automatically try to recover from all errors.
			fmt.Printf("Consumer error: %v (%v)\n", err, msg)
		}
	}

	consumer.Close()
}
