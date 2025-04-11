package target

import (
	"fmt"
	"net/url"
	"strings"
)

// Target represents a scan target
type Target struct {
	URL      string
	IP       string
	Hostname string
	Port     int
	Protocol string
	Path     string
}

// TargetManager handles target processing and management
type TargetManager struct {
	targets []*Target
}

// NewTargetManager creates a new target manager
func NewTargetManager() *TargetManager {
	return &TargetManager{
		targets: make([]*Target, 0),
	}
}

// AddTarget adds a target to the manager
func (m *TargetManager) AddTarget(targetStr string) error {
	target, err := ParseTarget(targetStr)
	if err != nil {
		return err
	}

	m.targets = append(m.targets, target)
	return nil
}

// GetTargets returns all targets
func (m *TargetManager) GetTargets() []*Target {
	return m.targets
}

// ParseTarget parses a target string into a Target struct
func ParseTarget(targetStr string) (*Target, error) {
	target := &Target{}

	// Add protocol if not present
	if !strings.Contains(targetStr, "://") {
		// Default to http if no protocol specified
		targetStr = "http://" + targetStr
	}

	// Parse URL
	parsedURL, err := url.Parse(targetStr)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	target.URL = targetStr
	target.Protocol = parsedURL.Scheme
	target.Path = parsedURL.Path

	// Extract hostname and port
	hostport := parsedURL.Host
	if strings.Contains(hostport, ":") {
		parts := strings.Split(hostport, ":")
		target.Hostname = parts[0]
		
		// Parse port
		var port int
		_, err := fmt.Sscanf(parts[1], "%d", &port)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}
		target.Port = port
	} else {
		target.Hostname = hostport
		
		// Set default port based on protocol
		switch target.Protocol {
		case "http":
			target.Port = 80
		case "https":
			target.Port = 443
		default:
			target.Port = 0
		}
	}

	return target, nil
}

// EnrichTarget enriches a target with additional information
func EnrichTarget(target *Target) error {
	// This is a placeholder for target enrichment logic
	// In a real implementation, this would perform DNS lookups, service detection, etc.
	return nil
}

// FilterTargets filters targets based on criteria
func FilterTargets(targets []*Target, criteria map[string]string) []*Target {
	// This is a placeholder for target filtering logic
	// In a real implementation, this would filter targets based on various criteria
	return targets
}
