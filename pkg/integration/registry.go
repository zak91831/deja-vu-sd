package integration

import (
	"fmt"
	"time"
)

// ComponentRegistry manages component registration and discovery
type ComponentRegistry struct {
	// Components contains registered components by ID
	Components map[string]Component
	
	// ComponentsByType contains components by type
	ComponentsByType map[string][]Component
	
	// Logger is the registry logger
	Logger Logger
}

// NewComponentRegistry creates a new component registry
func NewComponentRegistry(logger Logger) *ComponentRegistry {
	return &ComponentRegistry{
		Components:      make(map[string]Component),
		ComponentsByType: make(map[string][]Component),
		Logger:          logger,
	}
}

// RegisterComponent registers a component
func (r *ComponentRegistry) RegisterComponent(component Component) error {
	// Check if component already exists
	if _, exists := r.Components[component.ID()]; exists {
		return fmt.Errorf("component already exists: %s", component.ID())
	}
	
	// Register component
	r.Components[component.ID()] = component
	
	// Register component by type
	componentType := component.Type()
	r.ComponentsByType[componentType] = append(r.ComponentsByType[componentType], component)
	
	r.Logger.Info("Registered component: %s (%s) of type %s", component.Name(), component.ID(), componentType)
	
	return nil
}

// GetComponent gets a component by ID
func (r *ComponentRegistry) GetComponent(id string) (Component, error) {
	component, exists := r.Components[id]
	if !exists {
		return nil, fmt.Errorf("component not found: %s", id)
	}
	
	return component, nil
}

// GetComponentsByType gets components by type
func (r *ComponentRegistry) GetComponentsByType(componentType string) []Component {
	return r.ComponentsByType[componentType]
}

// GetAllComponents gets all registered components
func (r *ComponentRegistry) GetAllComponents() []Component {
	var components []Component
	
	for _, component := range r.Components {
		components = append(components, component)
	}
	
	return components
}

// ComponentFactory creates components
type ComponentFactory struct {
	// Registry is the component registry
	Registry *ComponentRegistry
	
	// Creators contains component creators by type
	Creators map[string]ComponentCreator
	
	// Logger is the factory logger
	Logger Logger
}

// ComponentCreator is an interface for component creators
type ComponentCreator interface {
	// CreateComponent creates a component
	CreateComponent(id, name, description string, parameters map[string]interface{}) (Component, error)
	
	// Type returns the component type
	Type() string
}

// NewComponentFactory creates a new component factory
func NewComponentFactory(registry *ComponentRegistry, logger Logger) *ComponentFactory {
	return &ComponentFactory{
		Registry: registry,
		Creators: make(map[string]ComponentCreator),
		Logger:   logger,
	}
}

// RegisterCreator registers a component creator
func (f *ComponentFactory) RegisterCreator(creator ComponentCreator) {
	f.Creators[creator.Type()] = creator
	f.Logger.Info("Registered component creator for type: %s", creator.Type())
}

// CreateComponent creates a component
func (f *ComponentFactory) CreateComponent(componentType, id, name, description string, parameters map[string]interface{}) (Component, error) {
	// Check if creator exists
	creator, exists := f.Creators[componentType]
	if !exists {
		return nil, fmt.Errorf("component creator not found for type: %s", componentType)
	}
	
	// Create component
	component, err := creator.CreateComponent(id, name, description, parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to create component: %w", err)
	}
	
	// Register component
	if err := f.Registry.RegisterComponent(component); err != nil {
		return nil, fmt.Errorf("failed to register component: %w", err)
	}
	
	return component, nil
}

// WorkflowRegistry manages workflow registration and discovery
type WorkflowRegistry struct {
	// Workflows contains registered workflows by ID
	Workflows map[string]*Workflow
	
	// WorkflowsByTag contains workflows by tag
	WorkflowsByTag map[string][]*Workflow
	
	// Logger is the registry logger
	Logger Logger
}

// NewWorkflowRegistry creates a new workflow registry
func NewWorkflowRegistry(logger Logger) *WorkflowRegistry {
	return &WorkflowRegistry{
		Workflows:     make(map[string]*Workflow),
		WorkflowsByTag: make(map[string][]*Workflow),
		Logger:        logger,
	}
}

// RegisterWorkflow registers a workflow
func (r *WorkflowRegistry) RegisterWorkflow(workflow *Workflow) error {
	// Check if workflow already exists
	if _, exists := r.Workflows[workflow.ID]; exists {
		return fmt.Errorf("workflow already exists: %s", workflow.ID)
	}
	
	// Register workflow
	r.Workflows[workflow.ID] = workflow
	
	// Register workflow by tags
	if tags, exists := workflow.Metadata["tags"]; exists {
		if tagList, ok := tags.([]string); ok {
			for _, tag := range tagList {
				r.WorkflowsByTag[tag] = append(r.WorkflowsByTag[tag], workflow)
			}
		}
	}
	
	r.Logger.Info("Registered workflow: %s (%s)", workflow.Name, workflow.ID)
	
	return nil
}

// GetWorkflow gets a workflow by ID
func (r *WorkflowRegistry) GetWorkflow(id string) (*Workflow, error) {
	workflow, exists := r.Workflows[id]
	if !exists {
		return nil, fmt.Errorf("workflow not found: %s", id)
	}
	
	return workflow, nil
}

// GetWorkflowsByTag gets workflows by tag
func (r *WorkflowRegistry) GetWorkflowsByTag(tag string) []*Workflow {
	return r.WorkflowsByTag[tag]
}

// GetAllWorkflows gets all registered workflows
func (r *WorkflowRegistry) GetAllWorkflows() []*Workflow {
	var workflows []*Workflow
	
	for _, workflow := range r.Workflows {
		workflows = append(workflows, workflow)
	}
	
	return workflows
}

// WorkflowExecutor executes workflows
type WorkflowExecutor struct {
	// Registry is the component registry
	Registry *ComponentRegistry
	
	// Options contains executor options
	Options *ExecutorOptions
	
	// Logger is the executor logger
	Logger Logger
}

// ExecutorOptions contains executor options
type ExecutorOptions struct {
	// EnableParallelExecution indicates whether to enable parallel execution
	EnableParallelExecution bool
	
	// MaxConcurrentExecutions is the maximum concurrent executions
	MaxConcurrentExecutions int
	
	// DefaultTimeout is the default execution timeout
	DefaultTimeout time.Duration
	
	// DefaultRetries is the default number of retries
	DefaultRetries int
}

// NewWorkflowExecutor creates a new workflow executor
func NewWorkflowExecutor(registry *ComponentRegistry, options *ExecutorOptions, logger Logger) *WorkflowExecutor {
	return &WorkflowExecutor{
		Registry: registry,
		Options:  options,
		Logger:   logger,
	}
}

// ExecuteWorkflow executes a workflow
func (e *WorkflowExecutor) ExecuteWorkflow(workflow *Workflow, parameters map[string]interface{}) (*ExecutionResult, error) {
	// Create execution context
	context := &ExecutionContext{
		WorkflowID:  workflow.ID,
		Parameters:  parameters,
		Variables:   make(map[string]interface{}),
		Results:     make(map[string]*ExecutionResult),
		StartTime:   time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	
	// Initialize variables
	for key, value := range workflow.Variables {
		context.Variables[key] = value
	}
	
	// Execute workflow
	result, err := e.executeWorkflowSteps(workflow, context)
	if err != nil {
		return nil, fmt.Errorf("failed to execute workflow: %w", err)
	}
	
	return result, nil
}

// executeWorkflowSteps executes workflow steps
func (e *WorkflowExecutor) executeWorkflowSteps(workflow *Workflow, context *ExecutionContext) (*ExecutionResult, error) {
	var lastResult *ExecutionResult
	
	// Execute each step
	for _, step := range workflow.Steps {
		// Check step condition
		if step.Condition != "" {
			// This is a placeholder for condition evaluation
			// A real implementation would evaluate the condition
		}
		
		// Create step context
		stepContext := &ExecutionContext{
			WorkflowID:  context.WorkflowID,
			StepID:      step.ID,
			Parameters:  step.Parameters,
			Variables:   context.Variables,
			Results:     context.Results,
			Parent:      context,
			StartTime:   time.Now(),
			Metadata:    make(map[string]interface{}),
		}
		
		// Get component
		component, err := e.Registry.GetComponent(step.ComponentID)
		if err != nil {
			return nil, fmt.Errorf("component not found: %s", step.ComponentID)
		}
		
		// Execute component
		e.Logger.Info("Executing step: %s (%s)", step.Name, step.ID)
		
		var result *ExecutionResult
		
		// Execute with retries
		retries := step.Retries
		if retries == 0 {
			retries = e.Options.DefaultRetries
		}
		
		for i := 0; i <= retries; i++ {
			// Execute component
			result, err = component.Execute(stepContext)
			
			// Break if successful
			if err == nil {
				break
			}
			
			// Log retry
			if i < retries {
				e.Logger.Warn("Retrying step: %s (%s), attempt %d/%d", step.Name, step.ID, i+1, retries)
			}
		}
		
		// Handle execution error
		if err != nil {
			e.Logger.Error("Failed to execute step: %s (%s): %v", step.Name, step.ID, err)
			
			// Create error result
			result = &ExecutionResult{
				ComponentID: component.ID(),
				StepID:      step.ID,
				Status:      "error",
				Error:       err,
				StartTime:   stepContext.StartTime,
				EndTime:     time.Now(),
				Duration:    time.Since(stepContext.StartTime),
				Metadata:    make(map[string]interface{}),
			}
			
			// Handle failure
			if step.OnFailure != "" {
				// This is a placeholder for failure handling
				// A real implementation would handle the failure
			}
			
			// Store result
			context.Results[step.ID] = result
			
			// Return error if no failure handler
			if step.OnFailure == "" {
				return result, fmt.Errorf("step execution failed: %w", err)
			}
		} else {
			// Handle success
			e.Logger.Info("Successfully executed step: %s (%s)", step.Name, step.ID)
			
			// Store result
			context.Results[step.ID] = result
			
			// Handle success
			if step.OnSuccess != "" {
				// This is a placeholder for success handling
				// A real implementation would handle the success
			}
		}
		
		lastResult = result
	}
	
	// Create workflow result
	workflowResult := &ExecutionResult{
		ComponentID: "workflow",
		StepID:      "workflow",
		Status:      "completed",
		Data:        context.Results,
		StartTime:   context.StartTime,
		EndTime:     time.Now(),
		Duration:    time.Since(context.StartTime),
		Metadata:    make(map[string]interface{}),
	}
	
	return workflowResult, nil
}

// NewExecutorOptions creates new executor options
func NewExecutorOptions() *ExecutorOptions {
	return &ExecutorOptions{
		EnableParallelExecution: true,
		MaxConcurrentExecutions: 5,
		DefaultTimeout:          60 * time.Second,
		DefaultRetries:          3,
	}
}
