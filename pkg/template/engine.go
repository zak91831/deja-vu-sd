package template

import (
	"encoding/json"
	"fmt"
	"time"
)

// TemplateEngine is the main engine for template processing
type TemplateEngine struct {
	// Library is the template library
	Library *TemplateLibrary
	
	// Executor is the template executor
	Executor *TemplateExecutor
	
	// Preprocessor is the template preprocessor
	Preprocessor *TemplatePreprocessor
	
	// Postprocessor is the template postprocessor
	Postprocessor *TemplatePostprocessor
}

// NewTemplateEngine creates a new template engine
func NewTemplateEngine(basePath string) *TemplateEngine {
	library := NewTemplateLibrary(basePath)
	
	return &TemplateEngine{
		Library:       library,
		Executor:      NewTemplateExecutor(library.Registry),
		Preprocessor:  NewTemplatePreprocessor(),
		Postprocessor: NewTemplatePostprocessor(),
	}
}

// LoadTemplates loads templates from a directory
func (e *TemplateEngine) LoadTemplates(dir string) error {
	return e.Library.LoadTemplates(dir)
}

// ExecuteTemplate executes a template
func (e *TemplateEngine) ExecuteTemplate(id string, target string, options map[string]interface{}) (interface{}, error) {
	// Get template
	template, exists := e.Library.GetTemplate(id)
	if !exists {
		return nil, fmt.Errorf("template not found: %s", id)
	}
	
	// Preprocess template
	preprocessedTemplate, err := e.Preprocessor.PreprocessTemplate(template, target, options)
	if err != nil {
		return nil, err
	}
	
	// Execute template
	result, err := e.Executor.ExecuteTemplate(preprocessedTemplate.ID, target, options)
	if err != nil {
		return nil, err
	}
	
	// Postprocess result
	postprocessedResult, err := e.Postprocessor.PostprocessResult(result, template, options)
	if err != nil {
		return nil, err
	}
	
	return postprocessedResult, nil
}

// ExecuteTemplates executes multiple templates
func (e *TemplateEngine) ExecuteTemplates(ids []string, target string, options map[string]interface{}) (interface{}, error) {
	var results []interface{}
	
	for _, id := range ids {
		result, err := e.ExecuteTemplate(id, target, options)
		if err != nil {
			// Log error but continue with other templates
			fmt.Printf("Error executing template %s: %v\n", id, err)
			continue
		}
		
		results = append(results, result)
	}
	
	return results, nil
}

// TemplatePreprocessor preprocesses templates before execution
type TemplatePreprocessor struct {
	// Processors are the preprocessing functions
	Processors []PreprocessFunc
}

// PreprocessFunc is a function that preprocesses a template
type PreprocessFunc func(*Template, string, map[string]interface{}) (*Template, error)

// NewTemplatePreprocessor creates a new template preprocessor
func NewTemplatePreprocessor() *TemplatePreprocessor {
	return &TemplatePreprocessor{
		Processors: []PreprocessFunc{
			preprocessVariables,
			preprocessHeaders,
			preprocessPayloads,
		},
	}
}

// AddProcessor adds a preprocessing function
func (p *TemplatePreprocessor) AddProcessor(processor PreprocessFunc) {
	p.Processors = append(p.Processors, processor)
}

// PreprocessTemplate preprocesses a template
func (p *TemplatePreprocessor) PreprocessTemplate(template *Template, target string, options map[string]interface{}) (*Template, error) {
	// Clone template to avoid modifying the original
	clonedTemplate, err := cloneTemplate(template)
	if err != nil {
		return nil, err
	}
	
	// Apply processors
	for _, processor := range p.Processors {
		clonedTemplate, err = processor(clonedTemplate, target, options)
		if err != nil {
			return nil, err
		}
	}
	
	return clonedTemplate, nil
}

// preprocessVariables preprocesses template variables
func preprocessVariables(template *Template, target string, options map[string]interface{}) (*Template, error) {
	// Add target to variables
	if template.Variables == nil {
		template.Variables = make(map[string]interface{})
	}
	
	template.Variables["target"] = target
	
	// Add options to variables
	for key, value := range options {
		template.Variables[key] = value
	}
	
	return template, nil
}

// preprocessHeaders preprocesses request headers
func preprocessHeaders(template *Template, target string, options map[string]interface{}) (*Template, error) {
	// Add default headers if not present
	for i, req := range template.Requests {
		if req.Headers == nil {
			req.Headers = make(map[string]string)
		}
		
		// Add User-Agent if not present
		if _, exists := req.Headers["User-Agent"]; !exists {
			req.Headers["User-Agent"] = "Deja-Vu-Scanner/2.0"
		}
		
		template.Requests[i] = req
	}
	
	return template, nil
}

// preprocessPayloads preprocesses request payloads
func preprocessPayloads(template *Template, target string, options map[string]interface{}) (*Template, error) {
	// Process payloads
	for i, req := range template.Requests {
		if len(req.Payloads) > 0 {
			// This is a placeholder for payload processing
			// A real implementation would process payloads
		}
		
		template.Requests[i] = req
	}
	
	return template, nil
}

// TemplatePostprocessor postprocesses results after execution
type TemplatePostprocessor struct {
	// Processors are the postprocessing functions
	Processors []PostprocessFunc
}

// PostprocessFunc is a function that postprocesses a result
type PostprocessFunc func(interface{}, *Template, map[string]interface{}) (interface{}, error)

// NewTemplatePostprocessor creates a new template postprocessor
func NewTemplatePostprocessor() *TemplatePostprocessor {
	return &TemplatePostprocessor{
		Processors: []PostprocessFunc{
			postprocessResults,
			postprocessMetadata,
		},
	}
}

// AddProcessor adds a postprocessing function
func (p *TemplatePostprocessor) AddProcessor(processor PostprocessFunc) {
	p.Processors = append(p.Processors, processor)
}

// PostprocessResult postprocesses a result
func (p *TemplatePostprocessor) PostprocessResult(result interface{}, template *Template, options map[string]interface{}) (interface{}, error) {
	// Apply processors
	var err error
	for _, processor := range p.Processors {
		result, err = processor(result, template, options)
		if err != nil {
			return nil, err
		}
	}
	
	return result, nil
}

// postprocessResults postprocesses execution results
func postprocessResults(result interface{}, template *Template, options map[string]interface{}) (interface{}, error) {
	// This is a placeholder for result postprocessing
	// A real implementation would process results
	
	return result, nil
}

// postprocessMetadata postprocesses result metadata
func postprocessMetadata(result interface{}, template *Template, options map[string]interface{}) (interface{}, error) {
	// This is a placeholder for metadata postprocessing
	// A real implementation would process metadata
	
	return result, nil
}

// TemplateCompiler compiles templates
type TemplateCompiler struct {
	// Optimizers are the optimization functions
	Optimizers []OptimizeFunc
}

// OptimizeFunc is a function that optimizes a template
type OptimizeFunc func(*Template) (*Template, error)

// NewTemplateCompiler creates a new template compiler
func NewTemplateCompiler() *TemplateCompiler {
	return &TemplateCompiler{
		Optimizers: []OptimizeFunc{
			optimizeRequests,
			optimizeMatchers,
			optimizeExtractors,
		},
	}
}

// AddOptimizer adds an optimization function
func (c *TemplateCompiler) AddOptimizer(optimizer OptimizeFunc) {
	c.Optimizers = append(c.Optimizers, optimizer)
}

// CompileTemplate compiles a template
func (c *TemplateCompiler) CompileTemplate(template *Template) (*Template, error) {
	// Clone template to avoid modifying the original
	clonedTemplate, err := cloneTemplate(template)
	if err != nil {
		return nil, err
	}
	
	// Apply optimizers
	for _, optimizer := range c.Optimizers {
		clonedTemplate, err = optimizer(clonedTemplate)
		if err != nil {
			return nil, err
		}
	}
	
	return clonedTemplate, nil
}

// optimizeRequests optimizes template requests
func optimizeRequests(template *Template) (*Template, error) {
	// This is a placeholder for request optimization
	// A real implementation would optimize requests
	
	return template, nil
}

// optimizeMatchers optimizes template matchers
func optimizeMatchers(template *Template) (*Template, error) {
	// This is a placeholder for matcher optimization
	// A real implementation would optimize matchers
	
	return template, nil
}

// optimizeExtractors optimizes template extractors
func optimizeExtractors(template *Template) (*Template, error) {
	// This is a placeholder for extractor optimization
	// A real implementation would optimize extractors
	
	return template, nil
}

// TemplateAnalyzer analyzes templates
type TemplateAnalyzer struct {
	// Analyzers are the analysis functions
	Analyzers []AnalyzeFunc
}

// AnalyzeFunc is a function that analyzes a template
type AnalyzeFunc func(*Template) (map[string]interface{}, error)

// NewTemplateAnalyzer creates a new template analyzer
func NewTemplateAnalyzer() *TemplateAnalyzer {
	return &TemplateAnalyzer{
		Analyzers: []AnalyzeFunc{
			analyzeComplexity,
			analyzePerformance,
			analyzeQuality,
		},
	}
}

// AddAnalyzer adds an analysis function
func (a *TemplateAnalyzer) AddAnalyzer(analyzer AnalyzeFunc) {
	a.Analyzers = append(a.Analyzers, analyzer)
}

// AnalyzeTemplate analyzes a template
func (a *TemplateAnalyzer) AnalyzeTemplate(template *Template) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	
	// Apply analyzers
	for _, analyzer := range a.Analyzers {
		result, err := analyzer(template)
		if err != nil {
			return nil, err
		}
		
		// Merge results
		for key, value := range result {
			results[key] = value
		}
	}
	
	return results, nil
}

// analyzeComplexity analyzes template complexity
func analyzeComplexity(template *Template) (map[string]interface{}, error) {
	// Calculate complexity metrics
	requestCount := len(template.Requests)
	workflowCount := len(template.Workflows)
	
	var matcherCount, extractorCount int
	for _, req := range template.Requests {
		matcherCount += len(req.Matchers)
		extractorCount += len(req.Extractors)
	}
	
	// Calculate complexity score
	complexityScore := requestCount + workflowCount + matcherCount/2 + extractorCount/2
	
	return map[string]interface{}{
		"complexity_score":  complexityScore,
		"request_count":     requestCount,
		"workflow_count":    workflowCount,
		"matcher_count":     matcherCount,
		"extractor_count":   extractorCount,
	}, nil
}

// analyzePerformance analyzes template performance
func analyzePerformance(template *Template) (map[string]interface{}, error) {
	// This is a placeholder for performance analysis
	// A real implementation would analyze performance
	
	return map[string]interface{}{
		"performance_score": 0,
	}, nil
}

// analyzeQuality analyzes template quality
func analyzeQuality(template *Template) (map[string]interface{}, error) {
	// This is a placeholder for quality analysis
	// A real implementation would analyze quality
	
	return map[string]interface{}{
		"quality_score": 0,
	}, nil
}

// TemplateDependencyResolver resolves template dependencies
type TemplateDependencyResolver struct {
	// Registry is the template registry
	Registry *TemplateRegistry
}

// NewTemplateDependencyResolver creates a new template dependency resolver
func NewTemplateDependencyResolver(registry *TemplateRegistry) *TemplateDependencyResolver {
	return &TemplateDependencyResolver{
		Registry: registry,
	}
}

// ResolveDependencies resolves template dependencies
func (r *TemplateDependencyResolver) ResolveDependencies(template *Template) ([]*Template, error) {
	var dependencies []*Template
	
	// Check for workflow dependencies
	for _, workflow := range template.Workflows {
		for _, step := range workflow.Logic {
			// Check if step executes another template
			if step.Execute != "" && step.Execute != template.ID {
				dependency, exists := r.Registry.GetTemplate(step.Execute)
				if !exists {
					return nil, fmt.Errorf("dependency not found: %s", step.Execute)
				}
				
				dependencies = append(dependencies, dependency)
			}
		}
	}
	
	return dependencies, nil
}

// TemplateScheduler schedules template execution
type TemplateScheduler struct {
	// Resolver is the template dependency resolver
	Resolver *TemplateDependencyResolver
}

// NewTemplateScheduler creates a new template scheduler
func NewTemplateScheduler(resolver *TemplateDependencyResolver) *TemplateScheduler {
	return &TemplateScheduler{
		Resolver: resolver,
	}
}

// ScheduleTemplates schedules template execution
func (s *TemplateScheduler) ScheduleTemplates(templates []*Template) ([]*Template, error) {
	// Build dependency graph
	dependencies := make(map[string][]string)
	
	for _, template := range templates {
		deps, err := s.Resolver.ResolveDependencies(template)
		if err != nil {
			return nil, err
		}
		
		for _, dep := range deps {
			dependencies[template.ID] = append(dependencies[template.ID], dep.ID)
		}
	}
	
	// Topological sort
	var scheduled []*Template
	visited := make(map[string]bool)
	
	var visit func(string) error
	visit = func(id string) error {
		if visited[id] {
			return nil
		}
		
		visited[id] = true
		
		for _, depID := range dependencies[id] {
			if err := visit(depID); err != nil {
				return err
			}
		}
		
		for _, template := range templates {
			if template.ID == id {
				scheduled = append(scheduled, template)
				break
			}
		}
		
		return nil
	}
	
	for _, template := range templates {
		if err := visit(template.ID); err != nil {
			return nil, err
		}
	}
	
	return scheduled, nil
}

// TemplateCache caches templates
type TemplateCache struct {
	// Cache contains cached templates
	Cache map[string]*Template
	
	// TTL is the cache time-to-live
	TTL time.Duration
	
	// Timestamps contains cache timestamps
	Timestamps map[string]time.Time
}

// NewTemplateCache creates a new template cache
func NewTemplateCache(ttl time.Duration) *TemplateCache {
	return &TemplateCache{
		Cache:      make(map[string]*Template),
		TTL:        ttl,
		Timestamps: make(map[string]time.Time),
	}
}

// Get gets a template from the cache
func (c *TemplateCache) Get(id string) (*Template, bool) {
	template, exists := c.Cache[id]
	if !exists {
		return nil, false
	}
	
	// Check if cache entry has expired
	timestamp, exists := c.Timestamps[id]
	if !exists || time.Since(timestamp) > c.TTL {
		delete(c.Cache, id)
		delete(c.Timestamps, id)
		return nil, false
	}
	
	return template, true
}

// Set sets a template in the cache
func (c *TemplateCache) Set(id string, template *Template) {
	c.Cache[id] = template
	c.Timestamps[id] = time.Now()
}

// Delete deletes a template from the cache
func (c *TemplateCache) Delete(id string) {
	delete(c.Cache, id)
	delete(c.Timestamps, id)
}

// Clear clears the cache
func (c *TemplateCache) Clear() {
	c.Cache = make(map[string]*Template)
	c.Timestamps = make(map[string]time.Time)
}

// TemplateFactory creates templates
type TemplateFactory struct {
	// Registry is the template registry
	Registry *TemplateRegistry
	
	// Generator is the template generator
	Generator *TemplateGenerator
}

// NewTemplateFactory creates a new template factory
func NewTemplateFactory(registry *TemplateRegistry, generator *TemplateGenerator) *TemplateFactory {
	return &TemplateFactory{
		Registry:  registry,
		Generator: generator,
	}
}

// CreateTemplate creates a template
func (f *TemplateFactory) CreateTemplate(options map[string]interface{}) (*Template, error) {
	// Generate template
	template, err := f.Generator.GenerateTemplate(options)
	if err != nil {
		return nil, err
	}
	
	// Register template
	f.Registry.RegisterTemplate(template)
	
	return template, nil
}

// CreateTemplateFromRequest creates a template from a request
func (f *TemplateFactory) CreateTemplateFromRequest(request *Request, options map[string]interface{}) (*Template, error) {
	// Generate template
	template, err := f.Generator.GenerateTemplateFromRequest(request, options)
	if err != nil {
		return nil, err
	}
	
	// Register template
	f.Registry.RegisterTemplate(template)
	
	return template, nil
}

// Helper functions

// cloneTemplate clones a template
func cloneTemplate(template *Template) (*Template, error) {
	// Marshal template to JSON
	data, err := json.Marshal(template)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal template: %w", err)
	}
	
	// Unmarshal JSON to new template
	var clonedTemplate Template
	if err := json.Unmarshal(data, &clonedTemplate); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template: %w", err)
	}
	
	return &clonedTemplate, nil
}
