package stream

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/confluentinc/confluent-kafka-go/kafka"
)

// NewProducer ...
func NewProducer() (*kafka.Producer, error) {
	configuration, err := autoDiscovery()
	if err != nil {
		return nil, err
	}

	librdConfig, err := NewLibrdConfigMap(configuration)
	if err != nil {
		return nil, err
	}

	return kafka.NewProducer(librdConfig)
}

// NewConsumer ...
func NewConsumer() (*kafka.Consumer, error) {
	configuration, err := autoDiscovery()
	if err != nil {
		return nil, err
	}

	librdConfig, err := NewLibrdConfigMap(configuration)

	if err != nil {
		return nil, err
	}

	return kafka.NewConsumer(librdConfig)
}

func environmentOrDefault(environmentName string, defaulValue string) string {
	if os.Getenv(environmentName) != "" {
		return os.Getenv(environmentName)
	}
	return defaulValue
}

func autoDiscovery() (*Configuration, error) {
	// TODO: Get environment name from struct Tags.
	configuration := &Configuration{
		Debug:             environmentOrDefault("DEBUG", "false"),
		BootstrapServers:  environmentOrDefault("KPROXY_KAFKA", ""),
		SecurityProtocol:  environmentOrDefault("SECURITY_PROTOCOL", ""),
		SASLMechanism:     environmentOrDefault("SASL_MECHANISM", ""),
		SASLPlainUsername: environmentOrDefault("SASL_PLAIN_USERNAME", ""),
		SASLPlainPassword: environmentOrDefault("SASL_PLAIN_PASSWORD", ""),
	}

	if configuration.SASLPlainUsername == "" || configuration.SASLPlainPassword == "" {
		configuration.SecurityProtocol = "PLAINTEXT"
	}

	if configuration.BootstrapServers == "" {
		return &Configuration{}, fmt.Errorf("Missing BootstrapServers")
	}

	return configuration, nil
}

// NewLibrdConfigMap sets the default Librd configuration. This can be extended or replaced by adding environment variables
// named as LIBRD__BOOTSTRAP_SERVERS, in this example it will be converted to 'bootstrap.servers' config.
func NewLibrdConfigMap(configuration *Configuration) (*kafka.ConfigMap, error) {
	// ConfigMap with librdkafka settings: https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
	librdOpts := &kafka.ConfigMap{
		"bootstrap.servers":       configuration.BootstrapServers,
		"security.protocol":       configuration.SecurityProtocol,
		"sasl.mechanism":          configuration.SASLMechanism,
		"sasl.username":           configuration.SASLPlainUsername,
		"socket.keepalive.enable": true,
		"log.connection.close":    false,
		"request.required.acks":   "all", // This is the default value for librdkafka, set here to be explicit
		"linger.ms":               0,     // Do not attempt to batch messages together before producing (default 0.5ms)
	}
	// Enable all debug mode in kafka if debug flag is set.
	if configuration.Debug == "true" {
		librdOpts.SetKey("debug", "broker,topic,msg")
	}
	// This converts LIBRD__* environment variables to librd options. The identifier is 'LIBRD__' and
	// after this the characters will be replaced lowercased and '_' will be replaced to '.'.
	// Example: 'LIBRD__GO_DELIVERY_REPORTS=true' will be transformed to option 'go.delivery.reports: true'.
	re := regexp.MustCompile("LIBRD__(.+?)$")
	for _, e := range os.Environ() {
		pair := strings.Split(e, "=")
		if sub := re.FindAllStringSubmatch(pair[0], -1); len(sub) > 0 {
			option := strings.Replace(strings.ToLower(sub[0][1]), "_", ".", -1)
			// Converts the value of the environment variable to its appropriate type. supported: int,float,bool and string.
			// Make sure your option is set by using one of these types otherwise you will get an type error when connecting to kafka.
			if i, err := strconv.ParseInt(pair[1], 10, 64); err == nil {
				librdOpts.SetKey(option, i)
			} else if f, err := strconv.ParseFloat(pair[1], 64); err == nil {
				librdOpts.SetKey(option, f)
			} else if b, err := strconv.ParseBool(pair[1]); err == nil {
				librdOpts.SetKey(option, b)
			} else {
				librdOpts.SetKey(option, pair[1])
			}
		}

	}

	_, err := json.MarshalIndent(librdOpts, "", "  ")

	if err != nil {
		return nil, err
	}

	// sets the key after so we don't log the password
	librdOpts.SetKey("sasl.password", configuration.SASLPlainPassword)

	return librdOpts, nil
}
