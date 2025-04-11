package timetravel

import (
	"github.com/dejavu/scanner/internal/config"
	"github.com/dejavu/scanner/pkg/core/engine"
)

// RegisterPlugin registers the time travel plugin with the scanner
func RegisterPlugin(scanner *engine.Scanner, cfg *config.Config) error {
	// Only register if time travel is enabled
	if !cfg.Features.TimeTravel.Enabled {
		return nil
	}

	// Create and register the plugin
	plugin := NewPlugin()
	return scanner.RegisterPlugin(plugin)
}
