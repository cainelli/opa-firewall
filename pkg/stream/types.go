package stream

// Configuration ...
type Configuration struct {
	Debug             string `env:"DEBUG"`
	BootstrapServers  string `env:"KPROXY_KAFKA"`
	SecurityProtocol  string `env:"SECURITY_PROTOCOL"`
	SASLMechanism     string `env:"SASL_MECHANISM"`
	SASLPlainUsername string `env:"SASL_PLAIN_USERNAME"`
	SASLPlainPassword string `env:"SASL_PLAIN_PASSWORD"`
}
