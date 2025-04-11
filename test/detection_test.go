package test

import (
	"testing"
)

// TestDetectionAccuracy tests the detection accuracy of the scanner
func TestDetectionAccuracy(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Test cases with known vulnerabilities
	testCases := []struct {
		name           string
		target         string
		workflowID     string
		expectedVulnCount int
		expectedSeverities []string
	}{
		{
			name:              "SQL Injection Test",
			target:            "http://test-server/sql-injection",
			workflowID:        "standard-scan",
			expectedVulnCount: 1,
			expectedSeverities: []string{"high"},
		},
		{
			name:              "XSS Test",
			target:            "http://test-server/xss",
			workflowID:        "standard-scan",
			expectedVulnCount: 1,
			expectedSeverities: []string{"medium"},
		},
		{
			name:              "Multiple Vulnerabilities Test",
			target:            "http://test-server/multiple",
			workflowID:        "comprehensive-scan",
			expectedVulnCount: 3,
			expectedSeverities: []string{"high", "medium", "low"},
		},
	}
	
	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create scan options
			options := NewScanOptions()
			options.WorkflowID = tc.workflowID
			
			// Perform scan
			result, err := api.Scan(tc.target, options)
			if err != nil {
				t.Fatalf("Failed to perform scan: %v", err)
			}
			
			// Check vulnerability count
			if len(result.Results) != tc.expectedVulnCount {
				t.Errorf("Expected %d vulnerabilities, got %d", tc.expectedVulnCount, len(result.Results))
			}
			
			// Check severities
			if len(result.Results) > 0 && len(tc.expectedSeverities) > 0 {
				for i, severity := range tc.expectedSeverities {
					if i < len(result.Results) && result.Results[i].Severity != severity {
						t.Errorf("Expected severity %s, got %s", severity, result.Results[i].Severity)
					}
				}
			}
		})
	}
}

// TestFalsePositiveReduction tests the false positive reduction capabilities
func TestFalsePositiveReduction(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Test cases with known false positives
	testCases := []struct {
		name           string
		target         string
		workflowID     string
		expectedVulnCount int
	}{
		{
			name:              "False Positive Test 1",
			target:            "http://test-server/false-positive-1",
			workflowID:        "standard-scan",
			expectedVulnCount: 0,
		},
		{
			name:              "False Positive Test 2",
			target:            "http://test-server/false-positive-2",
			workflowID:        "adaptive-scan",
			expectedVulnCount: 0,
		},
	}
	
	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create scan options
			options := NewScanOptions()
			options.WorkflowID = tc.workflowID
			
			// Perform scan
			result, err := api.Scan(tc.target, options)
			if err != nil {
				t.Fatalf("Failed to perform scan: %v", err)
			}
			
			// Check vulnerability count
			if len(result.Results) != tc.expectedVulnCount {
				t.Errorf("Expected %d vulnerabilities, got %d", tc.expectedVulnCount, len(result.Results))
			}
		})
	}
}

// TestConfidenceScoring tests the confidence scoring capabilities
func TestConfidenceScoring(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Test cases with different confidence levels
	testCases := []struct {
		name              string
		target            string
		workflowID        string
		expectedConfidence float64
		delta             float64
	}{
		{
			name:              "High Confidence Test",
			target:            "http://test-server/high-confidence",
			workflowID:        "standard-scan",
			expectedConfidence: 0.9,
			delta:             0.1,
		},
		{
			name:              "Medium Confidence Test",
			target:            "http://test-server/medium-confidence",
			workflowID:        "standard-scan",
			expectedConfidence: 0.6,
			delta:             0.1,
		},
		{
			name:              "Low Confidence Test",
			target:            "http://test-server/low-confidence",
			workflowID:        "standard-scan",
			expectedConfidence: 0.3,
			delta:             0.1,
		},
	}
	
	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create scan options
			options := NewScanOptions()
			options.WorkflowID = tc.workflowID
			
			// Perform scan
			result, err := api.Scan(tc.target, options)
			if err != nil {
				t.Fatalf("Failed to perform scan: %v", err)
			}
			
			// Check confidence
			if len(result.Results) > 0 {
				confidence := result.Results[0].Confidence
				if confidence < tc.expectedConfidence-tc.delta || confidence > tc.expectedConfidence+tc.delta {
					t.Errorf("Expected confidence around %f, got %f", tc.expectedConfidence, confidence)
				}
			} else {
				t.Errorf("No vulnerabilities found")
			}
		})
	}
}
