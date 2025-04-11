package integration

import (
	"fmt"
	"time"
)

// IntegrationAPI provides a unified API for Deja Vu
type IntegrationAPI struct {
	// Manager is the integration manager
	Manager *IntegrationManager
	
	// ComponentRegistry is the component registry
	ComponentRegistry *ComponentRegistry
	
	// WorkflowRegistry is the workflow registry
	WorkflowRegistry *WorkflowRegistry
	
	// WorkflowExecutor is the workflow executor
	WorkflowExecutor *WorkflowExecutor
	
	// ComponentFactory is the component factory
	ComponentFactory *ComponentFactory
	
	// WorkflowFactory is the workflow factory
	WorkflowFactory *WorkflowFactory
	
	// Logger is the API logger
	Logger Logger
}

// NewIntegrationAPI creates a new integration API
func NewIntegrationAPI(logger Logger) *IntegrationAPI {
	// Create component registry
	componentRegistry := NewComponentRegistry(logger)
	
	// Create workflow registry
	workflowRegistry := NewWorkflowRegistry(logger)
	
	// Create component factory
	componentFactory := NewComponentFactory(componentRegistry, logger)
	
	// Create workflow factory
	workflowFactory := NewWorkflowFactory()
	
	// Create workflow executor
	workflowExecutor := NewWorkflowExecutor(componentRegistry, NewExecutorOptions(), logger)
	
	// Create integration manager
	manager := NewIntegrationManager(logger)
	
	return &IntegrationAPI{
		Manager:           manager,
		ComponentRegistry: componentRegistry,
		WorkflowRegistry:  workflowRegistry,
		WorkflowExecutor:  workflowExecutor,
		ComponentFactory:  componentFactory,
		WorkflowFactory:   workflowFactory,
		Logger:            logger,
	}
}

// Initialize initializes the integration API
func (a *IntegrationAPI) Initialize() error {
	a.Logger.Info("Initializing Deja Vu Integration API")
	
	// Register component adapters
	a.registerComponentAdapters()
	
	// Register standard workflows
	a.registerStandardWorkflows()
	
	a.Logger.Info("Deja Vu Integration API initialized successfully")
	
	return nil
}

// registerComponentAdapters registers component adapters
func (a *IntegrationAPI) registerComponentAdapters() {
	// Register time travel adapter
	a.ComponentFactory.RegisterCreator(NewTimeTravelAdapter(nil, nil))
	
	// Register persona adapter
	a.ComponentFactory.RegisterCreator(NewPersonaAdapter(nil, nil))
	
	// Register adaptive adapter
	a.ComponentFactory.RegisterCreator(NewAdaptiveAdapter(nil, nil))
	
	// Register scanner adapter
	a.ComponentFactory.RegisterCreator(NewScannerAdapter(nil, nil))
}

// registerStandardWorkflows registers standard workflows
func (a *IntegrationAPI) registerStandardWorkflows() {
	// Create standard workflow
	standardWorkflow := a.WorkflowFactory.CreateStandardWorkflow(
		"standard-scan",
		"Standard Scan",
		"Standard vulnerability scanning workflow",
	)
	
	// Register standard workflow
	a.WorkflowRegistry.RegisterWorkflow(standardWorkflow)
	
	// Create time travel workflow
	timeTravelWorkflow := a.WorkflowFactory.CreateTimeTravelWorkflow(
		"timetravel-scan",
		"Time Travel Scan",
		"Historical vulnerability scanning workflow",
	)
	
	// Register time travel workflow
	a.WorkflowRegistry.RegisterWorkflow(timeTravelWorkflow)
	
	// Create persona workflows
	personaWorkflows := map[string]string{
		"standard":   "Standard Scanner",
		"stealthy":   "Stealthy Scanner",
		"aggressive": "Aggressive Scanner",
		"apt":        "APT Scanner",
	}
	
	for personaID, personaName := range personaWorkflows {
		// Create persona workflow
		personaWorkflow := a.WorkflowFactory.CreatePersonaWorkflow(
			fmt.Sprintf("persona-%s-scan", personaID),
			fmt.Sprintf("%s Scan", personaName),
			fmt.Sprintf("Personality-driven vulnerability scanning workflow using %s persona", personaName),
			personaID,
		)
		
		// Register persona workflow
		a.WorkflowRegistry.RegisterWorkflow(personaWorkflow)
	}
	
	// Create adaptive workflow
	adaptiveWorkflow := a.WorkflowFactory.CreateAdaptiveWorkflow(
		"adaptive-scan",
		"Adaptive Scan",
		"Adaptive vulnerability scanning workflow",
	)
	
	// Register adaptive workflow
	a.WorkflowRegistry.RegisterWorkflow(adaptiveWorkflow)
	
	// Create comprehensive workflow
	comprehensiveWorkflow := a.WorkflowFactory.CreateComprehensiveWorkflow(
		"comprehensive-scan",
		"Comprehensive Scan",
		"Comprehensive vulnerability scanning workflow using all advanced features",
	)
	
	// Register comprehensive workflow
	a.WorkflowRegistry.RegisterWorkflow(comprehensiveWorkflow)
}

// Scan performs a vulnerability scan
func (a *IntegrationAPI) Scan(target string, options *ScanOptions) (*ScanResult, error) {
	a.Logger.Info("Starting scan for target: %s", target)
	
	// Get workflow
	workflowID := options.WorkflowID
	if workflowID == "" {
		workflowID = "standard-scan"
	}
	
	workflow, err := a.WorkflowRegistry.GetWorkflow(workflowID)
	if err != nil {
		return nil, fmt.Errorf("workflow not found: %w", err)
	}
	
	// Create parameters
	parameters := map[string]interface{}{
		"target": target,
	}
	
	// Add options to parameters
	for key, value := range options.Parameters {
		parameters[key] = value
	}
	
	// Execute workflow
	result, err := a.WorkflowExecutor.ExecuteWorkflow(workflow, parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to execute workflow: %w", err)
	}
	
	// Create scan result
	scanResult := &ScanResult{
		Target:     target,
		WorkflowID: workflowID,
		Status:     result.Status,
		StartTime:  result.StartTime,
		EndTime:    result.EndTime,
		Duration:   result.Duration,
		Results:    make([]*VulnerabilityResult, 0),
		Metadata:   make(map[string]interface{}),
	}
	
	// Process results
	// This is a placeholder for result processing
	// A real implementation would process the results to extract vulnerabilities
	
	a.Logger.Info("Scan completed for target: %s", target)
	
	return scanResult, nil
}

// ScanOptions contains scan options
type ScanOptions struct {
	// WorkflowID is the workflow ID
	WorkflowID string
	
	// Parameters contains scan parameters
	Parameters map[string]interface{}
}

// ScanResult represents a scan result
type ScanResult struct {
	// Target is the scan target
	Target string
	
	// WorkflowID is the workflow ID
	WorkflowID string
	
	// Status is the scan status
	Status string
	
	// StartTime is the scan start time
	StartTime time.Time
	
	// EndTime is the scan end time
	EndTime time.Time
	
	// Duration is the scan duration
	Duration time.Duration
	
	// Results contains vulnerability results
	Results []*VulnerabilityResult
	
	// Metadata contains additional metadata
	Metadata map[string]interface{}
}

// VulnerabilityResult represents a vulnerability result
type VulnerabilityResult struct {
	// ID is the vulnerability ID
	ID string
	
	// Name is the vulnerability name
	Name string
	
	// Description is the vulnerability description
	Description string
	
	// Severity is the vulnerability severity
	Severity string
	
	// Evidence is the vulnerability evidence
	Evidence string
	
	// Location is the vulnerability location
	Location string
	
	// Confidence is the vulnerability confidence
	Confidence float64
	
	// Metadata contains additional metadata
	Metadata map[string]interface{}
}

// GetAvailableWorkflows gets available workflows
func (a *IntegrationAPI) GetAvailableWorkflows() []*Workflow {
	return a.WorkflowRegistry.GetAllWorkflows()
}

// GetWorkflow gets a workflow by ID
func (a *IntegrationAPI) GetWorkflow(id string) (*Workflow, error) {
	return a.WorkflowRegistry.GetWorkflow(id)
}

// NewScanOptions creates new scan options
func NewScanOptions() *ScanOptions {
	return &ScanOptions{
		WorkflowID:  "standard-scan",
		Parameters:  make(map[string]interface{}),
	}
}

// DefaultLogger is a simple logger implementation
type DefaultLogger struct{}

// NewDefaultLogger creates a new default logger
func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{}
}

// Debug logs a debug message
func (l *DefaultLogger) Debug(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}

// Info logs an info message
func (l *DefaultLogger) Info(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

// Warn logs a warning message
func (l *DefaultLogger) Warn(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

// Error logs an error message
func (l *DefaultLogger) Error(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}
