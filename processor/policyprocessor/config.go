package policyprocessor

import (
	"fmt"

	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/component"
)

// Config defines the configuration for the policy processor.
type Config struct {
	// Providers is the list of policy providers to use.
	Providers []policy.ProviderConfig `mapstructure:"providers"`
}

var _ component.Config = (*Config)(nil)

// Validate checks if the processor configuration is valid.
func (cfg *Config) Validate() error {
	if len(cfg.Providers) == 0 {
		return fmt.Errorf("at least one provider is required")
	}
	for i, p := range cfg.Providers {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("provider[%d]: %w", i, err)
		}
	}
	return nil
}
