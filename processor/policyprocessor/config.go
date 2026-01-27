package policyprocessor

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
)

// Config defines the configuration for the policy processor.
type Config struct {
	// PolicyFile is the path to a JSON file containing policies.
	// The file will be watched for changes and policies will be reloaded automatically.
	PolicyFile string `mapstructure:"policy_file"`

	// PollInterval is how often to check for policy file changes.
	// Default: 30s
	PollInterval time.Duration `mapstructure:"poll_interval"`
}

var _ component.Config = (*Config)(nil)

// Validate checks if the processor configuration is valid.
func (cfg *Config) Validate() error {
	if cfg.PolicyFile == "" {
		return errors.New("policy_file is required")
	}
	return nil
}
