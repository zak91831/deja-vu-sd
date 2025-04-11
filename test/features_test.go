package test

import (
	"fmt"
	"testing"
	"time"
)

// TestTimeTravelScanning tests the time travel scanning capability
func TestTimeTravelScanning(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Create scan options
	options := NewScanOptions()
	options.WorkflowID = "timetravel-scan"
	options.Parameters["start_date"] = time.Now().AddDate(-1, 0, 0)
	options.Parameters["end_date"] = time.Now()
	
	// Perform scan
	result, err := api.Scan("example.com", options)
	if err != nil {
		t.Fatalf("Failed to perform time travel scan: %v", err)
	}
	
	// Check scan result
	if result.Target != "example.com" {
		t.Errorf("Expected target to be example.com, got %s", result.Target)
	}
	
	if result.WorkflowID != "timetravel-scan" {
		t.Errorf("Expected workflow ID to be timetravel-scan, got %s", result.WorkflowID)
	}
	
	if result.Status != "completed" {
		t.Errorf("Expected status to be completed, got %s", result.Status)
	}
}

// TestPersonaDrivenScanning tests the personality-driven scanning capability
func TestPersonaDrivenScanning(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Test each persona
	personas := []string{"standard", "stealthy", "aggressive", "apt"}
	
	for _, persona := range personas {
		// Create scan options
		options := NewScanOptions()
		options.WorkflowID = fmt.Sprintf("persona-%s-scan", persona)
		options.Parameters["persona"] = persona
		
		// Perform scan
		result, err := api.Scan("example.com", options)
		if err != nil {
			t.Fatalf("Failed to perform persona scan with %s: %v", persona, err)
		}
		
		// Check scan result
		if result.Target != "example.com" {
			t.Errorf("Expected target to be example.com, got %s", result.Target)
		}
		
		if result.WorkflowID != fmt.Sprintf("persona-%s-scan", persona) {
			t.Errorf("Expected workflow ID to be persona-%s-scan, got %s", persona, result.WorkflowID)
		}
		
		if result.Status != "completed" {
			t.Errorf("Expected status to be completed, got %s", result.Status)
		}
	}
}

// TestAdaptiveLearning tests the adaptive learning capability
func TestAdaptiveLearning(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Create scan options
	options := NewScanOptions()
	options.WorkflowID = "adaptive-scan"
	options.Parameters["templates"] = []string{"default", "custom"}
	
	// Perform scan
	result, err := api.Scan("example.com", options)
	if err != nil {
		t.Fatalf("Failed to perform adaptive scan: %v", err)
	}
	
	// Check scan result
	if result.Target != "example.com" {
		t.Errorf("Expected target to be example.com, got %s", result.Target)
	}
	
	if result.WorkflowID != "adaptive-scan" {
		t.Errorf("Expected workflow ID to be adaptive-scan, got %s", result.WorkflowID)
	}
	
	if result.Status != "completed" {
		t.Errorf("Expected status to be completed, got %s", result.Status)
	}
}

// TestComprehensiveScanning tests the comprehensive scanning capability
func TestComprehensiveScanning(t *testing.T) {
	// Create logger
	logger := NewTestLogger()
	
	// Create integration API
	api := NewIntegrationAPI(logger)
	
	// Initialize API
	err := api.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize integration API: %v", err)
	}
	
	// Create scan options
	options := NewScanOptions()
	options.WorkflowID = "comprehensive-scan"
	
	// Perform scan
	result, err := api.Scan("example.com", options)
	if err != nil {
		t.Fatalf("Failed to perform comprehensive scan: %v", err)
	}
	
	// Check scan result
	if result.Target != "example.com" {
		t.Errorf("Expected target to be example.com, got %s", result.Target)
	}
	
	if result.WorkflowID != "comprehensive-scan" {
		t.Errorf("Expected workflow ID to be comprehensive-scan, got %s", result.WorkflowID)
	}
	
	if result.Status != "completed" {
		t.Errorf("Expected status to be completed, got %s", result.Status)
	}
}
