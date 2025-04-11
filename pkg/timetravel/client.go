package timetravel

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dejavu/scanner/pkg/core/target"
)

// WaybackClient provides access to the Wayback Machine API
type WaybackClient struct {
	httpClient *http.Client
	maxSnapshots int
	maxAgeDays int
}

// NewWaybackClient creates a new Wayback Machine client
func NewWaybackClient(maxSnapshots, maxAgeDays int) *WaybackClient {
	return &WaybackClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		maxSnapshots: maxSnapshots,
		maxAgeDays: maxAgeDays,
	}
}

// GetHistoricalURLs retrieves historical URLs for a domain from the Wayback Machine
func (c *WaybackClient) GetHistoricalURLs(domain string) ([]string, error) {
	fmt.Printf("[WaybackClient] Retrieving historical URLs for %s\n", domain)
	
	// In a real implementation, this would make an API call to the Wayback Machine
	// For this prototype, we'll simulate the response
	
	// Simulate API delay
	time.Sleep(500 * time.Millisecond)
	
	// Return simulated historical URLs
	return []string{
		fmt.Sprintf("http://%s/old-login", domain),
		fmt.Sprintf("http://%s/deprecated-api", domain),
		fmt.Sprintf("http://%s/backup", domain),
		fmt.Sprintf("http://%s/dev", domain),
		fmt.Sprintf("http://%s/test", domain),
	}, nil
}

// CertificateClient provides access to certificate transparency logs
type CertificateClient struct {
	httpClient *http.Client
	maxCerts int
}

// NewCertificateClient creates a new certificate transparency client
func NewCertificateClient(maxCerts int) *CertificateClient {
	return &CertificateClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		maxCerts: maxCerts,
	}
}

// GetHistoricalDomains retrieves historical domains from certificate transparency logs
func (c *CertificateClient) GetHistoricalDomains(domain string) ([]string, error) {
	fmt.Printf("[CertificateClient] Retrieving historical domains for %s\n", domain)
	
	// In a real implementation, this would query certificate transparency logs
	// For this prototype, we'll simulate the response
	
	// Simulate API delay
	time.Sleep(500 * time.Millisecond)
	
	// Generate domain variations
	parts := splitDomain(domain)
	if len(parts) < 2 {
		return []string{}, nil
	}
	
	baseDomain := parts[len(parts)-2] + "." + parts[len(parts)-1]
	
	// Return simulated historical domains
	return []string{
		"staging." + baseDomain,
		"dev." + baseDomain,
		"test." + baseDomain,
		"api." + baseDomain,
		"old." + baseDomain,
	}, nil
}

// TimeTravelEnricher enriches targets with historical data
type TimeTravelEnricher struct {
	waybackClient *WaybackClient
	certClient *CertificateClient
}

// NewTimeTravelEnricher creates a new time travel enricher
func NewTimeTravelEnricher(waybackClient *WaybackClient, certClient *CertificateClient) *TimeTravelEnricher {
	return &TimeTravelEnricher{
		waybackClient: waybackClient,
		certClient: certClient,
	}
}

// EnrichTarget enriches a target with historical data
func (e *TimeTravelEnricher) EnrichTarget(target *target.Target) ([]*target.Target, error) {
	fmt.Printf("[TimeTravelEnricher] Enriching target: %s\n", target.URL)
	
	additionalTargets := make([]*target.Target, 0)
	
	// Get historical URLs from Wayback Machine
	if e.waybackClient != nil {
		historicalURLs, err := e.waybackClient.GetHistoricalURLs(target.Hostname)
		if err != nil {
			fmt.Printf("[TimeTravelEnricher] Error getting Wayback URLs: %v\n", err)
		} else {
			fmt.Printf("[TimeTravelEnricher] Found %d historical URLs\n", len(historicalURLs))
			
			// Convert historical URLs to targets
			for _, historicalURL := range historicalURLs {
				historicalTarget, err := target.ParseTarget(historicalURL)
				if err != nil {
					fmt.Printf("[TimeTravelEnricher] Error parsing historical URL: %v\n", err)
					continue
				}
				
				additionalTargets = append(additionalTargets, historicalTarget)
			}
		}
	}
	
	// Get historical domains from certificate transparency logs
	if e.certClient != nil {
		historicalDomains, err := e.certClient.GetHistoricalDomains(target.Hostname)
		if err != nil {
			fmt.Printf("[TimeTravelEnricher] Error getting historical domains: %v\n", err)
		} else {
			fmt.Printf("[TimeTravelEnricher] Found %d historical domains\n", len(historicalDomains))
			
			// Convert historical domains to targets
			for _, domain := range historicalDomains {
				// Create URL from domain
				historicalURL := fmt.Sprintf("%s://%s", target.Protocol, domain)
				historicalTarget, err := target.ParseTarget(historicalURL)
				if err != nil {
					fmt.Printf("[TimeTravelEnricher] Error parsing historical domain: %v\n", err)
					continue
				}
				
				additionalTargets = append(additionalTargets, historicalTarget)
			}
		}
	}
	
	return additionalTargets, nil
}

// Helper functions

// splitDomain splits a domain into its component parts
func splitDomain(domain string) []string {
	return strings.Split(domain, ".")
}
