package test

import (
	"testing"
	"time"
)

// TestEndToEndScanning tests the end-to-end scanning process
func TestEndToEndScanning(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Create scan options for comprehensive scan
	options := NewScanOptions()
	options.WorkflowID = "comprehensive-scan"
	options.Parameters["start_date"] = time.Now().AddDate(-1, 0, 0)
	options.Parameters["end_date"] = time.Now()
	options.Parameters["persona"] = "apt"
	options.Parameters["templates"] = []string{"default", "custom", "advanced"}
	
	// Perform scan
	result, err := api.Scan("https://example.com", options)
	if err != nil {
		t.Fatalf("Failed to perform end-to-end scan: %v", err)
	}
	
	// Check scan result
	if result.Target != "https://example.com" {
		t.Errorf("Expected target to be https://example.com, got %s", result.Target)
	}
	
	if result.WorkflowID != "comprehensive-scan" {
		t.Errorf("Expected workflow ID to be comprehensive-scan, got %s", result.WorkflowID)
	}
	
	if result.Status != "completed" {
		t.Errorf("Expected status to be completed, got %s", result.Status)
	}
	
	// Check scan duration
	if result.Duration < 1*time.Second {
		t.Errorf("Expected scan duration to be at least 1 second, got %v", result.Duration)
	}
}

// TestPerformanceScaling tests the performance scaling capabilities
func TestPerformanceScaling(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Test cases with different target counts
	testCases := []struct {
		name        string
		targetCount int
		maxDuration time.Duration
	}{
		{
			name:        "Small Scale Test",
			targetCount: 5,
			maxDuration: 10 * time.Second,
		},
		{
			name:        "Medium Scale Test",
			targetCount: 10,
			maxDuration: 20 * time.Second,
		},
	}
	
	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create targets
			var targets []string
			for i := 0; i < tc.targetCount; i++ {
				targets = append(targets, "https://example.com")
			}
			
			// Create scan options
			options := NewScanOptions()
			
			// Record start time
			startTime := time.Now()
			
			// Perform scans
			for _, target := range targets {
				_, err := api.Scan(target, options)
				if err != nil {
					t.Fatalf("Failed to perform scan: %v", err)
				}
			}
			
			// Calculate total duration
			duration := time.Since(startTime)
			
			// Check duration
			if duration > tc.maxDuration {
				t.Errorf("Expected total duration to be less than %v, got %v", tc.maxDuration, duration)
			}
		})
	}
}

// TestErrorHandling tests the error handling capabilities
func TestErrorHandling(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Test cases with error conditions
	testCases := []struct {
		name          string
		target        string
		workflowID    string
		expectError   bool
		errorContains string
	}{
		{
			name:          "Invalid Target Test",
			target:        "invalid-url",
			workflowID:    "standard-scan",
			expectError:   true,
			errorContains: "invalid",
		},
		{
			name:          "Invalid Workflow Test",
			target:        "https://example.com",
			workflowID:    "non-existent-workflow",
			expectError:   true,
			errorContains: "not found",
		},
	}
	
	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create scan options
			options := NewScanOptions()
			options.WorkflowID = tc.workflowID
			
			// Perform scan
			_, err := api.Scan(tc.target, options)
			
			// Check error
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if tc.errorContains != "" && !containsString(err.Error(), tc.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tc.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// Helper function to check if a string contains another string
func containsString(s, substr string) bool {
	return s != "" && substr != "" && s != substr && len(s) > len(substr) && s[len(s)-len(substr):] == substr
}
