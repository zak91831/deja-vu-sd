package timetravel

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dejavu/scanner/pkg/core/target"
	"github.com/dejavu/scanner/pkg/plugins"
)

// Plugin implements the time travel scanning functionality
type Plugin struct {
	config         map[string]interface{}
	waybackEnabled bool
	certEnabled    bool
	maxSnapshots   int
	maxAgeDays     int
	maxCerts       int
	httpClient     *http.Client
}

// NewPlugin creates a new time travel plugin
func NewPlugin() plugins.Plugin {
	return &Plugin{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the name of the plugin
func (p *Plugin) Name() string {
	return "timetravel"
}

// Version returns the version of the plugin
func (p *Plugin) Version() string {
	return "1.0.0"
}

// Initialize initializes the plugin with the provided configuration
func (p *Plugin) Initialize(config map[string]interface{}) error {
	p.config = config

	// Extract wayback machine configuration
	if wayback, ok := config["wayback_machine"].(map[string]interface{}); ok {
		if enabled, ok := wayback["enabled"].(bool); ok {
			p.waybackEnabled = enabled
		}
		if maxSnapshots, ok := wayback["max_snapshots"].(int); ok {
			p.maxSnapshots = maxSnapshots
		} else {
			p.maxSnapshots = 10 // Default
		}
		if maxAgeDays, ok := wayback["max_age_days"].(int); ok {
			p.maxAgeDays = maxAgeDays
		} else {
			p.maxAgeDays = 365 // Default
		}
	}

	// Extract certificate history configuration
	if certHistory, ok := config["cert_history"].(map[string]interface{}); ok {
		if enabled, ok := certHistory["enabled"].(bool); ok {
			p.certEnabled = enabled
		}
		if maxCerts, ok := certHistory["max_certs"].(int); ok {
			p.maxCerts = maxCerts
		} else {
			p.maxCerts = 5 // Default
		}
	}

	return nil
}

// Start starts the plugin
func (p *Plugin) Start() error {
	fmt.Println("[TimeTravel] Plugin started")
	return nil
}

// Stop stops the plugin
func (p *Plugin) Stop() error {
	fmt.Println("[TimeTravel] Plugin stopped")
	return nil
}

// Hooks returns a map of hook functions that the plugin provides
func (p *Plugin) Hooks() map[string]interface{} {
	return map[string]interface{}{
		"post_target_load": p.enrichTarget,
	}
}

// enrichTarget is called after a target is loaded
func (p *Plugin) enrichTarget(target *target.Target) []*target.Target {
	fmt.Printf("[TimeTravel] Enriching target: %s\n", target.URL)
	
	additionalTargets := make([]*target.Target, 0)
	
	// Get historical URLs from Wayback Machine
	if p.waybackEnabled {
		historicalURLs, err := p.getWaybackURLs(target.Hostname)
		if err != nil {
			fmt.Printf("[TimeTravel] Error getting Wayback URLs: %v\n", err)
		} else {
			fmt.Printf("[TimeTravel] Found %d historical URLs\n", len(historicalURLs))
			
			// Convert historical URLs to targets
			for _, historicalURL := range historicalURLs {
				historicalTarget, err := target.ParseTarget(historicalURL)
				if err != nil {
					fmt.Printf("[TimeTravel] Error parsing historical URL: %v\n", err)
					continue
				}
				
				additionalTargets = append(additionalTargets, historicalTarget)
			}
		}
	}
	
	// Get historical certificates
	if p.certEnabled {
		historicalDomains, err := p.getHistoricalCertificates(target.Hostname)
		if err != nil {
			fmt.Printf("[TimeTravel] Error getting historical certificates: %v\n", err)
		} else {
			fmt.Printf("[TimeTravel] Found %d historical domains from certificates\n", len(historicalDomains))
			
			// Convert historical domains to targets
			for _, domain := range historicalDomains {
				// Skip if domain is the same as the target
				if domain == target.Hostname {
					continue
				}
				
				// Create URL from domain
				historicalURL := fmt.Sprintf("%s://%s", target.Protocol, domain)
				historicalTarget, err := target.ParseTarget(historicalURL)
				if err != nil {
					fmt.Printf("[TimeTravel] Error parsing historical domain: %v\n", err)
					continue
				}
				
				additionalTargets = append(additionalTargets, historicalTarget)
			}
		}
	}
	
	return additionalTargets
}

// getWaybackURLs retrieves historical URLs from the Wayback Machine
func (p *Plugin) getWaybackURLs(domain string) ([]string, error) {
	// This is a simplified implementation
	// In a real implementation, we would use the Wayback Machine API
	
	// Wayback CDX API URL
	apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s&output=json&collapse=urlkey&limit=%d", 
		url.QueryEscape(domain), p.maxSnapshots)
	
	// Send request
	resp, err := p.httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query Wayback Machine: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Wayback Machine response: %w", err)
	}
	
	// Parse JSON response
	var cdxResponse [][]string
	if err := json.Unmarshal(body, &cdxResponse); err != nil {
		return nil, fmt.Errorf("failed to parse Wayback Machine response: %w", err)
	}
	
	// Skip header row
	if len(cdxResponse) <= 1 {
		return []string{}, nil
	}
	cdxResponse = cdxResponse[1:]
	
	// Extract URLs
	urls := make([]string, 0, len(cdxResponse))
	cutoffDate := time.Now().AddDate(0, 0, -p.maxAgeDays)
	
	for _, row := range cdxResponse {
		if len(row) < 3 {
			continue
		}
		
		// Parse timestamp
		timestamp := row[1]
		if len(timestamp) < 8 {
			continue
		}
		
		// Format: YYYYMMDDHHMMSS
		year, _ := fmt.Sscanf(timestamp[0:4], "%d", new(int))
		month, _ := fmt.Sscanf(timestamp[4:6], "%d", new(int))
		day, _ := fmt.Sscanf(timestamp[6:8], "%d", new(int))
		snapshotDate := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
		
		// Skip if older than cutoff
		if snapshotDate.Before(cutoffDate) {
			continue
		}
		
		// Original URL
		originalURL := row[2]
		
		// Add to list if not already present
		if !contains(urls, originalURL) {
			urls = append(urls, originalURL)
		}
	}
	
	return urls, nil
}

// getHistoricalCertificates retrieves historical domains from certificate transparency logs
func (p *Plugin) getHistoricalCertificates(domain string) ([]string, error) {
	// This is a simplified implementation
	// In a real implementation, we would use a certificate transparency log API
	
	// For now, we'll just return some dummy domains
	// In a real implementation, this would query certificate transparency logs
	
	// Simulate API call
	time.Sleep(500 * time.Millisecond)
	
	// Return dummy domains
	domains := []string{
		domain,
		"staging." + domain,
		"dev." + domain,
		"test." + domain,
		"beta." + domain,
	}
	
	// Limit to max certs
	if len(domains) > p.maxCerts {
		domains = domains[:p.maxCerts]
	}
	
	return domains, nil
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
