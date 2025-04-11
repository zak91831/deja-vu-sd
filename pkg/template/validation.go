package template

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TemplateValidator validates templates
type TemplateValidator struct {
	// Validators are the validation functions
	Validators []ValidationFunc
}

// ValidationFunc is a function that validates a template
type ValidationFunc func(*Template) error

// ValidationError represents a template validation error
type ValidationError struct {
	// Field is the field that failed validation
	Field string
	
	// Message is the error message
	Message string
}

// Error returns the error message
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// NewTemplateValidator creates a new template validator
func NewTemplateValidator() *TemplateValidator {
	return &TemplateValidator{
		Validators: []ValidationFunc{
			validateID,
			validateInfo,
			validateRequests,
			validateWorkflows,
			validateClassification,
		},
	}
}

// AddValidator adds a validation function
func (v *TemplateValidator) AddValidator(validator ValidationFunc) {
	v.Validators = append(v.Validators, validator)
}

// Validate validates a template
func (v *TemplateValidator) Validate(template *Template) error {
	for _, validator := range v.Validators {
		if err := validator(template); err != nil {
			return err
		}
	}
	
	return nil
}

// validateID validates the template ID
func validateID(template *Template) error {
	if template.ID == "" {
		return &ValidationError{
			Field:   "id",
			Message: "template ID is required",
		}
	}
	
	return nil
}

// validateInfo validates the template info
func validateInfo(template *Template) error {
	if template.Info.Name == "" {
		return &ValidationError{
			Field:   "info.name",
			Message: "template name is required",
		}
	}
	
	if template.Info.Severity == "" {
		return &ValidationError{
			Field:   "info.severity",
			Message: "template severity is required",
		}
	}
	
	// Validate severity
	validSeverities := []string{"info", "low", "medium", "high", "critical"}
	validSeverity := false
	
	for _, severity := range validSeverities {
		if strings.ToLower(template.Info.Severity) == severity {
			validSeverity = true
			break
		}
	}
	
	if !validSeverity {
		return &ValidationError{
			Field:   "info.severity",
			Message: "invalid severity, must be one of: info, low, medium, high, critical",
		}
	}
	
	return nil
}

// validateRequests validates the template requests
func validateRequests(template *Template) error {
	if len(template.Requests) == 0 && len(template.Workflows) == 0 {
		return &ValidationError{
			Field:   "requests/workflows",
			Message: "template must have at least one request or workflow",
		}
	}
	
	for i, req := range template.Requests {
		if req.Method == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("requests[%d].method", i),
				Message: "request method is required",
			}
		}
		
		if req.Path == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("requests[%d].path", i),
				Message: "request path is required",
			}
		}
		
		// Validate matchers
		for j, matcher := range req.Matchers {
			if matcher.Type == "" {
				return &ValidationError{
					Field:   fmt.Sprintf("requests[%d].matchers[%d].type", i, j),
					Message: "matcher type is required",
				}
			}
		}
		
		// Validate extractors
		for j, extractor := range req.Extractors {
			if extractor.Type == "" {
				return &ValidationError{
					Field:   fmt.Sprintf("requests[%d].extractors[%d].type", i, j),
					Message: "extractor type is required",
				}
			}
		}
	}
	
	return nil
}

// validateWorkflows validates the template workflows
func validateWorkflows(template *Template) error {
	for i, workflow := range template.Workflows {
		if workflow.ID == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("workflows[%d].id", i),
				Message: "workflow ID is required",
			}
		}
		
		if len(workflow.Logic) == 0 {
			return &ValidationError{
				Field:   fmt.Sprintf("workflows[%d].logic", i),
				Message: "workflow must have at least one step",
			}
		}
		
		// Validate workflow steps
		for j, step := range workflow.Logic {
			if step.ID == "" {
				return &ValidationError{
					Field:   fmt.Sprintf("workflows[%d].logic[%d].id", i, j),
					Message: "step ID is required",
				}
			}
			
			if step.Execute == "" {
				return &ValidationError{
					Field:   fmt.Sprintf("workflows[%d].logic[%d].execute", i, j),
					Message: "step execute is required",
				}
			}
		}
	}
	
	return nil
}

// validateClassification validates the template classification
func validateClassification(template *Template) error {
	if template.Classification == nil {
		// Classification is optional
		return nil
	}
	
	// Validate CWE
	if template.Classification.CWE != "" {
		if !strings.HasPrefix(template.Classification.CWE, "CWE-") {
			return &ValidationError{
				Field:   "classification.cwe",
				Message: "CWE must be in the format CWE-XXX",
			}
		}
	}
	
	// Validate CVSS
	if template.Classification.CVSS != "" {
		// Simple validation for CVSS format
		if !strings.Contains(template.Classification.CVSS, ":") {
			return &ValidationError{
				Field:   "classification.cvss",
				Message: "CVSS must be in the format X.X:X.X:X.X:X.X",
			}
		}
	}
	
	return nil
}

// TemplateVersioning handles template versioning
type TemplateVersioning struct {
	// VersionFormat is the format for version strings
	VersionFormat string
}

// NewTemplateVersioning creates a new template versioning
func NewTemplateVersioning() *TemplateVersioning {
	return &TemplateVersioning{
		VersionFormat: "v%d.%d.%d",
	}
}

// GenerateVersion generates a version string
func (v *TemplateVersioning) GenerateVersion(major, minor, patch int) string {
	return fmt.Sprintf(v.VersionFormat, major, minor, patch)
}

// ParseVersion parses a version string
func (v *TemplateVersioning) ParseVersion(version string) (int, int, int, error) {
	var major, minor, patch int
	
	_, err := fmt.Sscanf(version, v.VersionFormat, &major, &minor, &patch)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to parse version: %w", err)
	}
	
	return major, minor, patch, nil
}

// IncrementMajor increments the major version
func (v *TemplateVersioning) IncrementMajor(version string) (string, error) {
	major, minor, patch, err := v.ParseVersion(version)
	if err != nil {
		return "", err
	}
	
	return v.GenerateVersion(major+1, 0, 0), nil
}

// IncrementMinor increments the minor version
func (v *TemplateVersioning) IncrementMinor(version string) (string, error) {
	major, minor, patch, err := v.ParseVersion(version)
	if err != nil {
		return "", err
	}
	
	return v.GenerateVersion(major, minor+1, 0), nil
}

// IncrementPatch increments the patch version
func (v *TemplateVersioning) IncrementPatch(version string) (string, error) {
	major, minor, patch, err := v.ParseVersion(version)
	if err != nil {
		return "", err
	}
	
	return v.GenerateVersion(major, minor, patch+1), nil
}

// TemplateManager manages templates
type TemplateManager struct {
	// Loader is the template loader
	Loader *TemplateLoader
	
	// Writer is the template writer
	Writer *TemplateWriter
	
	// Validator is the template validator
	Validator *TemplateValidator
	
	// Versioning is the template versioning
	Versioning *TemplateVersioning
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(basePath string) *TemplateManager {
	return &TemplateManager{
		Loader:     NewTemplateLoader(basePath),
		Writer:     NewTemplateWriter(),
		Validator:  NewTemplateValidator(),
		Versioning: NewTemplateVersioning(),
	}
}

// LoadTemplate loads a template from a file
func (m *TemplateManager) LoadTemplate(path string) (*Template, error) {
	// Load template
	template, err := m.Loader.LoadTemplate(path)
	if err != nil {
		return nil, err
	}
	
	// Validate template
	if err := m.Validator.Validate(template); err != nil {
		return nil, err
	}
	
	return template, nil
}

// SaveTemplate saves a template to a file
func (m *TemplateManager) SaveTemplate(template *Template, path string) error {
	// Validate template
	if err := m.Validator.Validate(template); err != nil {
		return err
	}
	
	// Save template
	return m.Writer.WriteTemplate(template, path)
}

// UpdateTemplate updates a template
func (m *TemplateManager) UpdateTemplate(template *Template) (*Template, error) {
	// Update template
	template.Info.Updated = time.Now().Format("2006-01-02")
	
	// Validate template
	if err := m.Validator.Validate(template); err != nil {
		return nil, err
	}
	
	return template, nil
}

// TemplateRegistry manages template registries
type TemplateRegistry struct {
	// Templates contains registered templates
	Templates map[string]*Template
	
	// Tags contains templates by tag
	Tags map[string][]*Template
	
	// Categories contains templates by category
	Categories map[string][]*Template
	
	// Severities contains templates by severity
	Severities map[string][]*Template
}

// NewTemplateRegistry creates a new template registry
func NewTemplateRegistry() *TemplateRegistry {
	return &TemplateRegistry{
		Templates:  make(map[string]*Template),
		Tags:       make(map[string][]*Template),
		Categories: make(map[string][]*Template),
		Severities: make(map[string][]*Template),
	}
}

// RegisterTemplate registers a template
func (r *TemplateRegistry) RegisterTemplate(template *Template) {
	// Register template
	r.Templates[template.ID] = template
	
	// Register by tags
	for _, tag := range template.Tags {
		r.Tags[tag] = append(r.Tags[tag], template)
	}
	
	// Register by category
	r.Categories[template.Info.Category] = append(r.Categories[template.Info.Category], template)
	
	// Register by severity
	r.Severities[template.Info.Severity] = append(r.Severities[template.Info.Severity], template)
}

// UnregisterTemplate unregisters a template
func (r *TemplateRegistry) UnregisterTemplate(id string) {
	template, exists := r.Templates[id]
	if !exists {
		return
	}
	
	// Unregister template
	delete(r.Templates, id)
	
	// Unregister by tags
	for _, tag := range template.Tags {
		templates := r.Tags[tag]
		for i, t := range templates {
			if t.ID == id {
				r.Tags[tag] = append(templates[:i], templates[i+1:]...)
				break
			}
		}
	}
	
	// Unregister by category
	templates := r.Categories[template.Info.Category]
	for i, t := range templates {
		if t.ID == id {
			r.Categories[template.Info.Category] = append(templates[:i], templates[i+1:]...)
			break
		}
	}
	
	// Unregister by severity
	templates = r.Severities[template.Info.Severity]
	for i, t := range templates {
		if t.ID == id {
			r.Severities[template.Info.Severity] = append(templates[:i], templates[i+1:]...)
			break
		}
	}
}

// GetTemplate gets a template by ID
func (r *TemplateRegistry) GetTemplate(id string) (*Template, bool) {
	template, exists := r.Templates[id]
	return template, exists
}

// GetTemplatesByTag gets templates by tag
func (r *TemplateRegistry) GetTemplatesByTag(tag string) []*Template {
	return r.Tags[tag]
}

// GetTemplatesByCategory gets templates by category
func (r *TemplateRegistry) GetTemplatesByCategory(category string) []*Template {
	return r.Categories[category]
}

// GetTemplatesBySeverity gets templates by severity
func (r *TemplateRegistry) GetTemplatesBySeverity(severity string) []*Template {
	return r.Severities[severity]
}

// TemplateExporter exports templates
type TemplateExporter struct {
	// Formats are the supported export formats
	Formats []string
}

// NewTemplateExporter creates a new template exporter
func NewTemplateExporter() *TemplateExporter {
	return &TemplateExporter{
		Formats: []string{"json", "yaml"},
	}
}

// ExportTemplate exports a template to a format
func (e *TemplateExporter) ExportTemplate(template *Template, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(template, "", "  ")
	case "yaml":
		converter := NewTemplateConverter()
		return converter.ConvertToYAML(template)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// ExportTemplates exports multiple templates to a format
func (e *TemplateExporter) ExportTemplates(templates []*Template, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(templates, "", "  ")
	case "yaml":
		// Export each template to YAML and concatenate
		var yamlData []byte
		
		for _, template := range templates {
			converter := NewTemplateConverter()
			templateYAML, err := converter.ConvertToYAML(template)
			if err != nil {
				return nil, err
			}
			
			yamlData = append(yamlData, templateYAML...)
			yamlData = append(yamlData, []byte("---\n")...)
		}
		
		return yamlData, nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// TemplateImporter imports templates
type TemplateImporter struct {
	// Formats are the supported import formats
	Formats []string
}

// NewTemplateImporter creates a new template importer
func NewTemplateImporter() *TemplateImporter {
	return &TemplateImporter{
		Formats: []string{"json", "yaml"},
	}
}

// ImportTemplate imports a template from a format
func (i *TemplateImporter) ImportTemplate(data []byte, format string) (*Template, error) {
	switch format {
	case "json":
		var template Template
		if err := json.Unmarshal(data, &template); err != nil {
			return nil, fmt.Errorf("failed to parse template: %w", err)
		}
		return &template, nil
	case "yaml":
		converter := NewTemplateConverter()
		return converter.ConvertFromYAML(data)
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}
}

// ImportTemplates imports multiple templates from a format
func (i *TemplateImporter) ImportTemplates(data []byte, format string) ([]*Template, error) {
	switch format {
	case "json":
		var templates []*Template
		if err := json.Unmarshal(data, &templates); err != nil {
			return nil, fmt.Errorf("failed to parse templates: %w", err)
		}
		return templates, nil
	case "yaml":
		// Split YAML by document separator and import each template
		yamlDocs := strings.Split(string(data), "---")
		var templates []*Template
		
		for _, yamlDoc := range yamlDocs {
			if strings.TrimSpace(yamlDoc) == "" {
				continue
			}
			
			converter := NewTemplateConverter()
			template, err := converter.ConvertFromYAML([]byte(yamlDoc))
			if err != nil {
				return nil, err
			}
			
			templates = append(templates, template)
		}
		
		return templates, nil
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}
}

// TemplateMigrator migrates templates between versions
type TemplateMigrator struct {
	// Migrations are the migration functions
	Migrations map[string]MigrationFunc
}

// MigrationFunc is a function that migrates a template
type MigrationFunc func(*Template) (*Template, error)

// NewTemplateMigrator creates a new template migrator
func NewTemplateMigrator() *TemplateMigrator {
	return &TemplateMigrator{
		Migrations: make(map[string]MigrationFunc),
	}
}

// AddMigration adds a migration function
func (m *TemplateMigrator) AddMigration(version string, migration MigrationFunc) {
	m.Migrations[version] = migration
}

// MigrateTemplate migrates a template to a version
func (m *TemplateMigrator) MigrateTemplate(template *Template, targetVersion string) (*Template, error) {
	// Get current version from metadata
	currentVersion, ok := template.Metadata["version"].(string)
	if !ok {
		currentVersion = "v1.0.0"
	}
	
	// Check if migration is needed
	if currentVersion == targetVersion {
		return template, nil
	}
	
	// Get migration function
	migration, exists := m.Migrations[targetVersion]
	if !exists {
		return nil, fmt.Errorf("no migration available for version %s", targetVersion)
	}
	
	// Migrate template
	migratedTemplate, err := migration(template)
	if err != nil {
		return nil, fmt.Errorf("failed to migrate template: %w", err)
	}
	
	// Update version
	migratedTemplate.Metadata["version"] = targetVersion
	
	return migratedTemplate, nil
}

// TemplateGenerator generates templates
type TemplateGenerator struct {
	// Builder is the template builder
	Builder *TemplateBuilder
}

// NewTemplateGenerator creates a new template generator
func NewTemplateGenerator() *TemplateGenerator {
	return &TemplateGenerator{
		Builder: NewTemplateBuilder(),
	}
}

// GenerateTemplate generates a template
func (g *TemplateGenerator) GenerateTemplate(options map[string]interface{}) (*Template, error) {
	// Reset builder
	g.Builder = NewTemplateBuilder()
	
	// Set template ID
	if id, ok := options["id"].(string); ok {
		g.Builder.SetID(id)
	} else {
		g.Builder.SetID(fmt.Sprintf("template-%d", time.Now().Unix()))
	}
	
	// Set template name
	if name, ok := options["name"].(string); ok {
		g.Builder.SetName(name)
	}
	
	// Set template description
	if description, ok := options["description"].(string); ok {
		g.Builder.SetDescription(description)
	}
	
	// Set template severity
	if severity, ok := options["severity"].(string); ok {
		g.Builder.SetSeverity(severity)
	} else {
		g.Builder.SetSeverity("info")
	}
	
	// Set template category
	if category, ok := options["category"].(string); ok {
		g.Builder.SetCategory(category)
	}
	
	// Add tags
	if tags, ok := options["tags"].([]string); ok {
		for _, tag := range tags {
			g.Builder.AddTag(tag)
		}
	}
	
	// Add authors
	if authors, ok := options["authors"].([]string); ok {
		for _, author := range authors {
			g.Builder.AddAuthor(author)
		}
	}
	
	// Add references
	if references, ok := options["references"].([]string); ok {
		for _, reference := range references {
			g.Builder.AddReference(reference)
		}
	}
	
	// Set current dates
	g.Builder.SetCurrentDates()
	
	// Build template
	return g.Builder.Build(), nil
}

// GenerateTemplateFromRequest generates a template from a request
func (g *TemplateGenerator) GenerateTemplateFromRequest(request *Request, options map[string]interface{}) (*Template, error) {
	// Generate template
	template, err := g.GenerateTemplate(options)
	if err != nil {
		return nil, err
	}
	
	// Add request
	template.Requests = append(template.Requests, request)
	
	return template, nil
}

// TemplateLibrary manages a library of templates
type TemplateLibrary struct {
	// Registry is the template registry
	Registry *TemplateRegistry
	
	// Manager is the template manager
	Manager *TemplateManager
	
	// Exporter is the template exporter
	Exporter *TemplateExporter
	
	// Importer is the template importer
	Importer *TemplateImporter
	
	// Migrator is the template migrator
	Migrator *TemplateMigrator
	
	// Generator is the template generator
	Generator *TemplateGenerator
}

// NewTemplateLibrary creates a new template library
func NewTemplateLibrary(basePath string) *TemplateLibrary {
	return &TemplateLibrary{
		Registry:  NewTemplateRegistry(),
		Manager:   NewTemplateManager(basePath),
		Exporter:  NewTemplateExporter(),
		Importer:  NewTemplateImporter(),
		Migrator:  NewTemplateMigrator(),
		Generator: NewTemplateGenerator(),
	}
}

// LoadTemplates loads templates from a directory
func (l *TemplateLibrary) LoadTemplates(dir string) error {
	// Load templates
	if err := l.Manager.Loader.LoadTemplates(dir); err != nil {
		return err
	}
	
	// Register templates
	for id, template := range l.Manager.Loader.Templates {
		l.Registry.RegisterTemplate(template)
	}
	
	return nil
}

// GetTemplate gets a template by ID
func (l *TemplateLibrary) GetTemplate(id string) (*Template, bool) {
	return l.Registry.GetTemplate(id)
}

// SaveTemplate saves a template
func (l *TemplateLibrary) SaveTemplate(template *Template, path string) error {
	// Validate template
	if err := l.Manager.Validator.Validate(template); err != nil {
		return err
	}
	
	// Save template
	if err := l.Manager.SaveTemplate(template, path); err != nil {
		return err
	}
	
	// Register template
	l.Registry.RegisterTemplate(template)
	
	return nil
}

// ExportTemplate exports a template
func (l *TemplateLibrary) ExportTemplate(id, format string) ([]byte, error) {
	// Get template
	template, exists := l.Registry.GetTemplate(id)
	if !exists {
		return nil, fmt.Errorf("template not found: %s", id)
	}
	
	// Export template
	return l.Exporter.ExportTemplate(template, format)
}

// ImportTemplate imports a template
func (l *TemplateLibrary) ImportTemplate(data []byte, format string) (*Template, error) {
	// Import template
	template, err := l.Importer.ImportTemplate(data, format)
	if err != nil {
		return nil, err
	}
	
	// Validate template
	if err := l.Manager.Validator.Validate(template); err != nil {
		return nil, err
	}
	
	// Register template
	l.Registry.RegisterTemplate(template)
	
	return template, nil
}

// GenerateTemplate generates a template
func (l *TemplateLibrary) GenerateTemplate(options map[string]interface{}) (*Template, error) {
	// Generate template
	template, err := l.Generator.GenerateTemplate(options)
	if err != nil {
		return nil, err
	}
	
	// Validate template
	if err := l.Manager.Validator.Validate(template); err != nil {
		return nil, err
	}
	
	// Register template
	l.Registry.RegisterTemplate(template)
	
	return template, nil
}

// TemplateExecutor executes templates
type TemplateExecutor struct {
	// Registry is the template registry
	Registry *TemplateRegistry
}

// NewTemplateExecutor creates a new template executor
func NewTemplateExecutor(registry *TemplateRegistry) *TemplateExecutor {
	return &TemplateExecutor{
		Registry: registry,
	}
}

// ExecuteTemplate executes a template
func (e *TemplateExecutor) ExecuteTemplate(id string, target string, options map[string]interface{}) (interface{}, error) {
	// Get template
	template, exists := e.Registry.GetTemplate(id)
	if !exists {
		return nil, fmt.Errorf("template not found: %s", id)
	}
	
	// Execute template
	// This is a placeholder for the actual implementation
	// A real implementation would execute the template against the target
	
	return nil, fmt.Errorf("template execution not implemented")
}

// ExecuteTemplates executes multiple templates
func (e *TemplateExecutor) ExecuteTemplates(ids []string, target string, options map[string]interface{}) (interface{}, error) {
	// Execute templates
	// This is a placeholder for the actual implementation
	// A real implementation would execute the templates against the target
	
	return nil, fmt.Errorf("template execution not implemented")
}
