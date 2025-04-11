package persona

import (
	"github.com/dejavu/scanner/internal/config"
	"github.com/dejavu/scanner/pkg/core/engine"
)

// RegisterPlugin registers the persona plugin with the scanner
func RegisterPlugin(scanner *engine.Scanner, cfg *config.Config) error {
	// Only register if persona is enabled
	if !cfg.Features.Persona.Enabled {
		return nil
	}

	// Create and register the plugin
	plugin := NewPlugin()
	return scanner.RegisterPlugin(plugin)
}
