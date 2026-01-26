package policyprocessor

import (
	"go.opentelemetry.io/collector/component"
)

// Config defines the configuration for the policy processor.
type Config struct {
	// Enabled controls whether the processor is active.
	Enabled bool `mapstructure:"enabled"`
}

var _ component.Config = (*Config)(nil)

// Validate checks if the processor configuration is valid.
func (cfg *Config) Validate() error {
	return nil
}
