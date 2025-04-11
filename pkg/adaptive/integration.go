package adaptive

import (
	"github.com/dejavu/scanner/internal/config"
	"github.com/dejavu/scanner/pkg/core/engine"
)

// RegisterPlugin registers the adaptive learning plugin with the scanner
func RegisterPlugin(scanner *engine.Scanner, cfg *config.Config) error {
	// Only register if adaptive learning is enabled
	if !cfg.Features.Adaptive.Enabled {
		return nil
	}

	// Create and register the plugin
	plugin := NewPlugin()
	return scanner.RegisterPlugin(plugin)
}
