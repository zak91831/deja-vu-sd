package template

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"
)

// Template represents a vulnerability scanning template
type Template struct {
	// ID is the unique identifier for the template
	ID string `json:"id"`
	
	// Info contains metadata about the template
	Info TemplateInfo `json:"info"`
	
	// Variables contains template variables
	Variables map[string]interface{} `json:"variables,omitempty"`
	
	// Requests contains the HTTP requests to make
	Requests []*Request `json:"requests,omitempty"`
	
	// Workflows contains multi-step workflows
	Workflows []*Workflow `json:"workflows,omitempty"`
	
	// Tags contains template tags for categorization
	Tags []string `json:"tags,omitempty"`
	
	// Classification contains template classification information
	Classification *Classification `json:"classification,omitempty"`
	
	// Authors contains template authors
	Authors []string `json:"authors,omitempty"`
	
	// References contains reference URLs
	References []string `json:"references,omitempty"`
	
	// Metadata contains additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// TemplateInfo contains metadata about a template
type TemplateInfo struct {
	// Name is the template name
	Name string `json:"name"`
	
	// Description is the template description
	Description string `json:"description"`
	
	// Severity is the vulnerability severity
	Severity string `json:"severity"`
	
	// Category is the vulnerability category
	Category string `json:"category"`
	
	// Tags contains template tags
	Tags []string `json:"tags,omitempty"`
	
	// Created is the template creation date
	Created string `json:"created,omitempty"`
	
	// Updated is the template update date
	Updated string `json:"updated,omitempty"`
}

// Request represents an HTTP request in a template
type Request struct {
	// ID is the request identifier
	ID string `json:"id,omitempty"`
	
	// Name is the request name
	Name string `json:"name,omitempty"`
	
	// Description is the request description
	Description string `json:"description,omitempty"`
	
	// Protocol is the request protocol
	Protocol string `json:"protocol,omitempty"`
	
	// Method is the HTTP method
	Method string `json:"method"`
	
	// Path is the request path
	Path string `json:"path"`
	
	// Headers are the HTTP headers
	Headers map[string]string `json:"headers,omitempty"`
	
	// Body is the request body
	Body string `json:"body,omitempty"`
	
	// Payloads contains payload lists for fuzzing
	Payloads map[string][]string `json:"payloads,omitempty"`
	
	// Matchers are the response matchers
	Matchers []*Matcher `json:"matchers,omitempty"`
	
	// Extractors are the response extractors
	Extractors []*Extractor `json:"extractors,omitempty"`
	
	// StopAtFirstMatch stops processing after first match
	StopAtFirstMatch bool `json:"stop_at_first_match,omitempty"`
	
	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int `json:"max_redirects,omitempty"`
	
	// PipelineRequests contains requests to execute in pipeline
	PipelineRequests []*PipelineRequest `json:"pipeline,omitempty"`
	
	// RaceCondition enables race condition testing
	RaceCondition bool `json:"race_condition,omitempty"`
	
	// RaceCount is the number of race requests to send
	RaceCount int `json:"race_count,omitempty"`
	
	// Variables contains request-specific variables
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// PipelineRequest represents a request in a pipeline
type PipelineRequest struct {
	// ID is the request identifier
	ID string `json:"id,omitempty"`
	
	// Name is the request name
	Name string `json:"name,omitempty"`
	
	// Description is the request description
	Description string `json:"description,omitempty"`
	
	// Protocol is the request protocol
	Protocol string `json:"protocol,omitempty"`
	
	// Method is the HTTP method
	Method string `json:"method"`
	
	// Path is the request path
	Path string `json:"path"`
	
	// Headers are the HTTP headers
	Headers map[string]string `json:"headers,omitempty"`
	
	// Body is the request body
	Body string `json:"body,omitempty"`
	
	// Matchers are the response matchers
	Matchers []*Matcher `json:"matchers,omitempty"`
	
	// Extractors are the response extractors
	Extractors []*Extractor `json:"extractors,omitempty"`
}

// Matcher represents a response matcher
type Matcher struct {
	// Type is the matcher type
	Type string `json:"type"`
	
	// Part is the part to match
	Part string `json:"part,omitempty"`
	
	// Condition is the condition for matching
	Condition string `json:"condition,omitempty"`
	
	// Value is the value to match
	Value interface{} `json:"value,omitempty"`
	
	// Values are the values to match
	Values []interface{} `json:"values,omitempty"`
	
	// Regex is the regex pattern to match
	Regex string `json:"regex,omitempty"`
	
	// Regexes are the regex patterns to match
	Regexes []string `json:"regexes,omitempty"`
	
	// DSL is the DSL expression to match
	DSL string `json:"dsl,omitempty"`
	
	// DSLs are the DSL expressions to match
	DSLs []string `json:"dsls,omitempty"`
	
	// Status is the status code to match
	Status []int `json:"status,omitempty"`
	
	// Size is the size to match
	Size []int `json:"size,omitempty"`
	
	// Words are the words to match
	Words []string `json:"words,omitempty"`
	
	// Binary is the binary data to match
	Binary []string `json:"binary,omitempty"`
	
	// Negate inverts the match result
	Negate bool `json:"negate,omitempty"`
	
	// CaseSensitive determines whether matching is case-sensitive
	CaseSensitive bool `json:"case_sensitive,omitempty"`
	
	// MatchAll determines whether all patterns must match
	MatchAll bool `json:"match_all,omitempty"`
}

// Extractor represents a response extractor
type Extractor struct {
	// Type is the extractor type
	Type string `json:"type"`
	
	// Part is the part to extract from
	Part string `json:"part,omitempty"`
	
	// Name is the extractor name
	Name string `json:"name,omitempty"`
	
	// Regex is the regex pattern to extract
	Regex string `json:"regex,omitempty"`
	
	// Regexes are the regex patterns to extract
	Regexes []string `json:"regexes,omitempty"`
	
	// Group is the regex group to extract
	Group int `json:"group,omitempty"`
	
	// JSON is the JSON path to extract
	JSON string `json:"json,omitempty"`
	
	// JSONs are the JSON paths to extract
	JSONs []string `json:"jsons,omitempty"`
	
	// XML is the XML path to extract
	XML string `json:"xml,omitempty"`
	
	// XMLs are the XML paths to extract
	XMLs []string `json:"xmls,omitempty"`
	
	// Attribute is the HTML attribute to extract
	Attribute string `json:"attribute,omitempty"`
	
	// DSL is the DSL expression to extract
	DSL string `json:"dsl,omitempty"`
	
	// DSLs are the DSL expressions to extract
	DSLs []string `json:"dsls,omitempty"`
}

// Workflow represents a multi-step workflow
type Workflow struct {
	// ID is the workflow identifier
	ID string `json:"id"`
	
	// Name is the workflow name
	Name string `json:"name,omitempty"`
	
	// Description is the workflow description
	Description string `json:"description,omitempty"`
	
	// Tags contains workflow tags
	Tags []string `json:"tags,omitempty"`
	
	// Variables contains workflow variables
	Variables map[string]interface{} `json:"variables,omitempty"`
	
	// Logic contains workflow logic
	Logic []*WorkflowStep `json:"logic"`
}

// WorkflowStep represents a step in a workflow
type WorkflowStep struct {
	// ID is the step identifier
	ID string `json:"id"`
	
	// Name is the step name
	Name string `json:"name,omitempty"`
	
	// Description is the step description
	Description string `json:"description,omitempty"`
	
	// Execute is the request to execute
	Execute string `json:"execute"`
	
	// Condition is the condition for execution
	Condition string `json:"condition,omitempty"`
	
	// NextSteps are the next steps to execute
	NextSteps []string `json:"next_steps,omitempty"`
	
	// OnSuccess are the steps to execute on success
	OnSuccess []string `json:"on_success,omitempty"`
	
	// OnFailure are the steps to execute on failure
	OnFailure []string `json:"on_failure,omitempty"`
}

// Classification contains template classification information
type Classification struct {
	// CVE is the CVE identifier
	CVE string `json:"cve,omitempty"`
	
	// CWE is the CWE identifier
	CWE string `json:"cwe,omitempty"`
	
	// CVSS is the CVSS score
	CVSS string `json:"cvss,omitempty"`
	
	// OWASP is the OWASP category
	OWASP string `json:"owasp,omitempty"`
	
	// WASC is the WASC category
	WASC string `json:"wasc,omitempty"`
	
	// PCI is the PCI DSS requirement
	PCI string `json:"pci,omitempty"`
	
	// HIPAA is the HIPAA requirement
	HIPAA string `json:"hipaa,omitempty"`
	
	// GDPR is the GDPR article
	GDPR string `json:"gdpr,omitempty"`
	
	// Custom contains custom classification information
	Custom map[string]string `json:"custom,omitempty"`
}

// TemplateLoader loads templates
type TemplateLoader struct {
	// BasePath is the base path for templates
	BasePath string
	
	// Templates contains loaded templates
	Templates map[string]*Template
	
	// Tags contains templates by tag
	Tags map[string][]*Template
	
	// Categories contains templates by category
	Categories map[string][]*Template
	
	// Severities contains templates by severity
	Severities map[string][]*Template
}

// NewTemplateLoader creates a new template loader
func NewTemplateLoader(basePath string) *TemplateLoader {
	return &TemplateLoader{
		BasePath:   basePath,
		Templates:  make(map[string]*Template),
		Tags:       make(map[string][]*Template),
		Categories: make(map[string][]*Template),
		Severities: make(map[string][]*Template),
	}
}

// LoadTemplate loads a template from a file
func (l *TemplateLoader) LoadTemplate(path string) (*Template, error) {
	// Read template file
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}
	
	// Parse template
	var template Template
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	
	// Validate template
	if err := l.ValidateTemplate(&template); err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}
	
	// Add template to loader
	l.Templates[template.ID] = &template
	
	// Add template to tags
	for _, tag := range template.Tags {
		l.Tags[tag] = append(l.Tags[tag], &template)
	}
	
	// Add template to categories
	l.Categories[template.Info.Category] = append(l.Categories[template.Info.Category], &template)
	
	// Add template to severities
	l.Severities[template.Info.Severity] = append(l.Severities[template.Info.Severity], &template)
	
	return &template, nil
}

// LoadTemplates loads all templates from a directory
func (l *TemplateLoader) LoadTemplates(dir string) error {
	// Get template files
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to list template files: %w", err)
	}
	
	// Load each template
	for _, file := range files {
		if _, err := l.LoadTemplate(file); err != nil {
			return err
		}
	}
	
	return nil
}

// GetTemplate gets a template by ID
func (l *TemplateLoader) GetTemplate(id string) (*Template, bool) {
	template, exists := l.Templates[id]
	return template, exists
}

// GetTemplatesByTag gets templates by tag
func (l *TemplateLoader) GetTemplatesByTag(tag string) []*Template {
	return l.Tags[tag]
}

// GetTemplatesByCategory gets templates by category
func (l *TemplateLoader) GetTemplatesByCategory(category string) []*Template {
	return l.Categories[category]
}

// GetTemplatesBySeverity gets templates by severity
func (l *TemplateLoader) GetTemplatesBySeverity(severity string) []*Template {
	return l.Severities[severity]
}

// ValidateTemplate validates a template
func (l *TemplateLoader) ValidateTemplate(template *Template) error {
	// Validate ID
	if template.ID == "" {
		return fmt.Errorf("template ID is required")
	}
	
	// Validate info
	if template.Info.Name == "" {
		return fmt.Errorf("template name is required")
	}
	
	if template.Info.Severity == "" {
		return fmt.Errorf("template severity is required")
	}
	
	// Validate requests or workflows
	if len(template.Requests) == 0 && len(template.Workflows) == 0 {
		return fmt.Errorf("template must have at least one request or workflow")
	}
	
	// Validate requests
	for i, req := range template.Requests {
		if req.Method == "" {
			return fmt.Errorf("request %d method is required", i)
		}
		
		if req.Path == "" {
			return fmt.Errorf("request %d path is required", i)
		}
	}
	
	// Validate workflows
	for i, workflow := range template.Workflows {
		if workflow.ID == "" {
			return fmt.Errorf("workflow %d ID is required", i)
		}
		
		if len(workflow.Logic) == 0 {
			return fmt.Errorf("workflow %d must have at least one step", i)
		}
		
		// Validate workflow steps
		for j, step := range workflow.Logic {
			if step.ID == "" {
				return fmt.Errorf("workflow %d step %d ID is required", i, j)
			}
			
			if step.Execute == "" {
				return fmt.Errorf("workflow %d step %d execute is required", i, j)
			}
		}
	}
	
	return nil
}

// TemplateWriter writes templates
type TemplateWriter struct{}

// NewTemplateWriter creates a new template writer
func NewTemplateWriter() *TemplateWriter {
	return &TemplateWriter{}
}

// WriteTemplate writes a template to a file
func (w *TemplateWriter) WriteTemplate(template *Template, path string) error {
	// Marshal template to JSON
	data, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}
	
	// Write template file
	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write template file: %w", err)
	}
	
	return nil
}

// TemplateBuilder builds templates
type TemplateBuilder struct {
	// Template is the template being built
	Template *Template
}

// NewTemplateBuilder creates a new template builder
func NewTemplateBuilder() *TemplateBuilder {
	return &TemplateBuilder{
		Template: &Template{
			Variables: make(map[string]interface{}),
			Requests:  make([]*Request, 0),
			Workflows: make([]*Workflow, 0),
			Tags:      make([]string, 0),
			Authors:   make([]string, 0),
			References: make([]string, 0),
			Metadata:  make(map[string]interface{}),
		},
	}
}

// SetID sets the template ID
func (b *TemplateBuilder) SetID(id string) *TemplateBuilder {
	b.Template.ID = id
	return b
}

// SetName sets the template name
func (b *TemplateBuilder) SetName(name string) *TemplateBuilder {
	b.Template.Info.Name = name
	return b
}

// SetDescription sets the template description
func (b *TemplateBuilder) SetDescription(description string) *TemplateBuilder {
	b.Template.Info.Description = description
	return b
}

// SetSeverity sets the template severity
func (b *TemplateBuilder) SetSeverity(severity string) *TemplateBuilder {
	b.Template.Info.Severity = severity
	return b
}

// SetCategory sets the template category
func (b *TemplateBuilder) SetCategory(category string) *TemplateBuilder {
	b.Template.Info.Category = category
	return b
}

// AddTag adds a tag to the template
func (b *TemplateBuilder) AddTag(tag string) *TemplateBuilder {
	b.Template.Tags = append(b.Template.Tags, tag)
	b.Template.Info.Tags = append(b.Template.Info.Tags, tag)
	return b
}

// AddAuthor adds an author to the template
func (b *TemplateBuilder) AddAuthor(author string) *TemplateBuilder {
	b.Template.Authors = append(b.Template.Authors, author)
	return b
}

// AddReference adds a reference to the template
func (b *TemplateBuilder) AddReference(reference string) *TemplateBuilder {
	b.Template.References = append(b.Template.References, reference)
	return b
}

// SetVariable sets a template variable
func (b *TemplateBuilder) SetVariable(name string, value interface{}) *TemplateBuilder {
	b.Template.Variables[name] = value
	return b
}

// AddRequest adds a request to the template
func (b *TemplateBuilder) AddRequest(request *Request) *TemplateBuilder {
	b.Template.Requests = append(b.Template.Requests, request)
	return b
}

// AddWorkflow adds a workflow to the template
func (b *TemplateBuilder) AddWorkflow(workflow *Workflow) *TemplateBuilder {
	b.Template.Workflows = append(b.Template.Workflows, workflow)
	return b
}

// SetClassification sets the template classification
func (b *TemplateBuilder) SetClassification(classification *Classification) *TemplateBuilder {
	b.Template.Classification = classification
	return b
}

// SetMetadata sets template metadata
func (b *TemplateBuilder) SetMetadata(key string, value interface{}) *TemplateBuilder {
	b.Template.Metadata[key] = value
	return b
}

// SetCreated sets the template creation date
func (b *TemplateBuilder) SetCreated(created string) *TemplateBuilder {
	b.Template.Info.Created = created
	return b
}

// SetUpdated sets the template update date
func (b *TemplateBuilder) SetUpdated(updated string) *TemplateBuilder {
	b.Template.Info.Updated = updated
	return b
}

// SetCurrentDates sets the template creation and update dates to the current date
func (b *TemplateBuilder) SetCurrentDates() *TemplateBuilder {
	now := time.Now().Format("2006-01-02")
	b.Template.Info.Created = now
	b.Template.Info.Updated = now
	return b
}

// Build builds the template
func (b *TemplateBuilder) Build() *Template {
	return b.Template
}

// RequestBuilder builds requests
type RequestBuilder struct {
	// Request is the request being built
	Request *Request
}

// NewRequestBuilder creates a new request builder
func NewRequestBuilder() *RequestBuilder {
	return &RequestBuilder{
		Request: &Request{
			Headers:   make(map[string]string),
			Payloads:  make(map[string][]string),
			Matchers:  make([]*Matcher, 0),
			Extractors: make([]*Extractor, 0),
			Variables: make(map[string]interface{}),
		},
	}
}

// SetID sets the request ID
func (b *RequestBuilder) SetID(id string) *RequestBuilder {
	b.Request.ID = id
	return b
}

// SetName sets the request name
func (b *RequestBuilder) SetName(name string) *RequestBuilder {
	b.Request.Name = name
	return b
}

// SetDescription sets the request description
func (b *RequestBuilder) SetDescription(description string) *RequestBuilder {
	b.Request.Description = description
	return b
}

// SetProtocol sets the request protocol
func (b *RequestBuilder) SetProtocol(protocol string) *RequestBuilder {
	b.Request.Protocol = protocol
	return b
}

// SetMethod sets the HTTP method
func (b *RequestBuilder) SetMethod(method string) *RequestBuilder {
	b.Request.Method = method
	return b
}

// SetPath sets the request path
func (b *RequestBuilder) SetPath(path string) *RequestBuilder {
	b.Request.Path = path
	return b
}

// SetHeader sets a request header
func (b *RequestBuilder) SetHeader(name, value string) *RequestBuilder {
	b.Request.Headers[name] = value
	return b
}

// SetBody sets the request body
func (b *RequestBuilder) SetBody(body string) *RequestBuilder {
	b.Request.Body = body
	return b
}

// AddPayload adds a payload to the request
func (b *RequestBuilder) AddPayload(name string, values []string) *RequestBuilder {
	b.Request.Payloads[name] = values
	return b
}

// AddMatcher adds a matcher to the request
func (b *RequestBuilder) AddMatcher(matcher *Matcher) *RequestBuilder {
	b.Request.Matchers = append(b.Request.Matchers, matcher)
	return b
}

// AddExtractor adds an extractor to the request
func (b *RequestBuilder) AddExtractor(extractor *Extractor) *RequestBuilder {
	b.Request.Extractors = append(b.Request.Extractors, extractor)
	return b
}

// SetStopAtFirstMatch sets whether to stop at first match
func (b *RequestBuilder) SetStopAtFirstMatch(stop bool) *RequestBuilder {
	b.Request.StopAtFirstMatch = stop
	return b
}

// SetMaxRedirects sets the maximum number of redirects to follow
func (b *RequestBuilder) SetMaxRedirects(max int) *RequestBuilder {
	b.Request.MaxRedirects = max
	return b
}

// AddPipelineRequest adds a pipeline request
func (b *RequestBuilder) AddPipelineRequest(request *PipelineRequest) *RequestBuilder {
	b.Request.PipelineRequests = append(b.Request.PipelineRequests, request)
	return b
}

// SetRaceCondition sets whether to enable race condition testing
func (b *RequestBuilder) SetRaceCondition(race bool) *RequestBuilder {
	b.Request.RaceCondition = race
	return b
}

// SetRaceCount sets the number of race requests to send
func (b *RequestBuilder) SetRaceCount(count int) *RequestBuilder {
	b.Request.RaceCount = count
	return b
}

// SetVariable sets a request variable
func (b *RequestBuilder) SetVariable(name string, value interface{}) *RequestBuilder {
	b.Request.Variables[name] = value
	return b
}

// Build builds the request
func (b *RequestBuilder) Build() *Request {
	return b.Request
}

// MatcherBuilder builds matchers
type MatcherBuilder struct {
	// Matcher is the matcher being built
	Matcher *Matcher
}

// NewMatcherBuilder creates a new matcher builder
func NewMatcherBuilder() *MatcherBuilder {
	return &MatcherBuilder{
		Matcher: &Matcher{},
	}
}

// SetType sets the matcher type
func (b *MatcherBuilder) SetType(matcherType string) *MatcherBuilder {
	b.Matcher.Type = matcherType
	return b
}

// SetPart sets the part to match
func (b *MatcherBuilder) SetPart(part string) *MatcherBuilder {
	b.Matcher.Part = part
	return b
}

// SetCondition sets the condition for matching
func (b *MatcherBuilder) SetCondition(condition string) *MatcherBuilder {
	b.Matcher.Condition = condition
	return b
}

// SetValue sets the value to match
func (b *MatcherBuilder) SetValue(value interface{}) *MatcherBuilder {
	b.Matcher.Value = value
	return b
}

// SetValues sets the values to match
func (b *MatcherBuilder) SetValues(values []interface{}) *MatcherBuilder {
	b.Matcher.Values = values
	return b
}

// SetRegex sets the regex pattern to match
func (b *MatcherBuilder) SetRegex(regex string) *MatcherBuilder {
	b.Matcher.Regex = regex
	return b
}

// SetRegexes sets the regex patterns to match
func (b *MatcherBuilder) SetRegexes(regexes []string) *MatcherBuilder {
	b.Matcher.Regexes = regexes
	return b
}

// SetDSL sets the DSL expression to match
func (b *MatcherBuilder) SetDSL(dsl string) *MatcherBuilder {
	b.Matcher.DSL = dsl
	return b
}

// SetDSLs sets the DSL expressions to match
func (b *MatcherBuilder) SetDSLs(dsls []string) *MatcherBuilder {
	b.Matcher.DSLs = dsls
	return b
}

// SetStatus sets the status codes to match
func (b *MatcherBuilder) SetStatus(status []int) *MatcherBuilder {
	b.Matcher.Status = status
	return b
}

// SetSize sets the sizes to match
func (b *MatcherBuilder) SetSize(size []int) *MatcherBuilder {
	b.Matcher.Size = size
	return b
}

// SetWords sets the words to match
func (b *MatcherBuilder) SetWords(words []string) *MatcherBuilder {
	b.Matcher.Words = words
	return b
}

// SetBinary sets the binary data to match
func (b *MatcherBuilder) SetBinary(binary []string) *MatcherBuilder {
	b.Matcher.Binary = binary
	return b
}

// SetNegate sets whether to negate the match result
func (b *MatcherBuilder) SetNegate(negate bool) *MatcherBuilder {
	b.Matcher.Negate = negate
	return b
}

// SetCaseSensitive sets whether matching is case-sensitive
func (b *MatcherBuilder) SetCaseSensitive(caseSensitive bool) *MatcherBuilder {
	b.Matcher.CaseSensitive = caseSensitive
	return b
}

// SetMatchAll sets whether all patterns must match
func (b *MatcherBuilder) SetMatchAll(matchAll bool) *MatcherBuilder {
	b.Matcher.MatchAll = matchAll
	return b
}

// Build builds the matcher
func (b *MatcherBuilder) Build() *Matcher {
	return b.Matcher
}

// ExtractorBuilder builds extractors
type ExtractorBuilder struct {
	// Extractor is the extractor being built
	Extractor *Extractor
}

// NewExtractorBuilder creates a new extractor builder
func NewExtractorBuilder() *ExtractorBuilder {
	return &ExtractorBuilder{
		Extractor: &Extractor{},
	}
}

// SetType sets the extractor type
func (b *ExtractorBuilder) SetType(extractorType string) *ExtractorBuilder {
	b.Extractor.Type = extractorType
	return b
}

// SetPart sets the part to extract from
func (b *ExtractorBuilder) SetPart(part string) *ExtractorBuilder {
	b.Extractor.Part = part
	return b
}

// SetName sets the extractor name
func (b *ExtractorBuilder) SetName(name string) *ExtractorBuilder {
	b.Extractor.Name = name
	return b
}

// SetRegex sets the regex pattern to extract
func (b *ExtractorBuilder) SetRegex(regex string) *ExtractorBuilder {
	b.Extractor.Regex = regex
	return b
}

// SetRegexes sets the regex patterns to extract
func (b *ExtractorBuilder) SetRegexes(regexes []string) *ExtractorBuilder {
	b.Extractor.Regexes = regexes
	return b
}

// SetGroup sets the regex group to extract
func (b *ExtractorBuilder) SetGroup(group int) *ExtractorBuilder {
	b.Extractor.Group = group
	return b
}

// SetJSON sets the JSON path to extract
func (b *ExtractorBuilder) SetJSON(jsonPath string) *ExtractorBuilder {
	b.Extractor.JSON = jsonPath
	return b
}

// SetJSONs sets the JSON paths to extract
func (b *ExtractorBuilder) SetJSONs(jsonPaths []string) *ExtractorBuilder {
	b.Extractor.JSONs = jsonPaths
	return b
}

// SetXML sets the XML path to extract
func (b *ExtractorBuilder) SetXML(xmlPath string) *ExtractorBuilder {
	b.Extractor.XML = xmlPath
	return b
}

// SetXMLs sets the XML paths to extract
func (b *ExtractorBuilder) SetXMLs(xmlPaths []string) *ExtractorBuilder {
	b.Extractor.XMLs = xmlPaths
	return b
}

// SetAttribute sets the HTML attribute to extract
func (b *ExtractorBuilder) SetAttribute(attribute string) *ExtractorBuilder {
	b.Extractor.Attribute = attribute
	return b
}

// SetDSL sets the DSL expression to extract
func (b *ExtractorBuilder) SetDSL(dsl string) *ExtractorBuilder {
	b.Extractor.DSL = dsl
	return b
}

// SetDSLs sets the DSL expressions to extract
func (b *ExtractorBuilder) SetDSLs(dsls []string) *ExtractorBuilder {
	b.Extractor.DSLs = dsls
	return b
}

// Build builds the extractor
func (b *ExtractorBuilder) Build() *Extractor {
	return b.Extractor
}

// WorkflowBuilder builds workflows
type WorkflowBuilder struct {
	// Workflow is the workflow being built
	Workflow *Workflow
}

// NewWorkflowBuilder creates a new workflow builder
func NewWorkflowBuilder() *WorkflowBuilder {
	return &WorkflowBuilder{
		Workflow: &Workflow{
			Tags:     make([]string, 0),
			Variables: make(map[string]interface{}),
			Logic:    make([]*WorkflowStep, 0),
		},
	}
}

// SetID sets the workflow ID
func (b *WorkflowBuilder) SetID(id string) *WorkflowBuilder {
	b.Workflow.ID = id
	return b
}

// SetName sets the workflow name
func (b *WorkflowBuilder) SetName(name string) *WorkflowBuilder {
	b.Workflow.Name = name
	return b
}

// SetDescription sets the workflow description
func (b *WorkflowBuilder) SetDescription(description string) *WorkflowBuilder {
	b.Workflow.Description = description
	return b
}

// AddTag adds a tag to the workflow
func (b *WorkflowBuilder) AddTag(tag string) *WorkflowBuilder {
	b.Workflow.Tags = append(b.Workflow.Tags, tag)
	return b
}

// SetVariable sets a workflow variable
func (b *WorkflowBuilder) SetVariable(name string, value interface{}) *WorkflowBuilder {
	b.Workflow.Variables[name] = value
	return b
}

// AddStep adds a step to the workflow
func (b *WorkflowBuilder) AddStep(step *WorkflowStep) *WorkflowBuilder {
	b.Workflow.Logic = append(b.Workflow.Logic, step)
	return b
}

// Build builds the workflow
func (b *WorkflowBuilder) Build() *Workflow {
	return b.Workflow
}

// WorkflowStepBuilder builds workflow steps
type WorkflowStepBuilder struct {
	// Step is the step being built
	Step *WorkflowStep
}

// NewWorkflowStepBuilder creates a new workflow step builder
func NewWorkflowStepBuilder() *WorkflowStepBuilder {
	return &WorkflowStepBuilder{
		Step: &WorkflowStep{
			NextSteps: make([]string, 0),
			OnSuccess: make([]string, 0),
			OnFailure: make([]string, 0),
		},
	}
}

// SetID sets the step ID
func (b *WorkflowStepBuilder) SetID(id string) *WorkflowStepBuilder {
	b.Step.ID = id
	return b
}

// SetName sets the step name
func (b *WorkflowStepBuilder) SetName(name string) *WorkflowStepBuilder {
	b.Step.Name = name
	return b
}

// SetDescription sets the step description
func (b *WorkflowStepBuilder) SetDescription(description string) *WorkflowStepBuilder {
	b.Step.Description = description
	return b
}

// SetExecute sets the request to execute
func (b *WorkflowStepBuilder) SetExecute(execute string) *WorkflowStepBuilder {
	b.Step.Execute = execute
	return b
}

// SetCondition sets the condition for execution
func (b *WorkflowStepBuilder) SetCondition(condition string) *WorkflowStepBuilder {
	b.Step.Condition = condition
	return b
}

// AddNextStep adds a next step to execute
func (b *WorkflowStepBuilder) AddNextStep(nextStep string) *WorkflowStepBuilder {
	b.Step.NextSteps = append(b.Step.NextSteps, nextStep)
	return b
}

// AddOnSuccess adds a step to execute on success
func (b *WorkflowStepBuilder) AddOnSuccess(onSuccess string) *WorkflowStepBuilder {
	b.Step.OnSuccess = append(b.Step.OnSuccess, onSuccess)
	return b
}

// AddOnFailure adds a step to execute on failure
func (b *WorkflowStepBuilder) AddOnFailure(onFailure string) *WorkflowStepBuilder {
	b.Step.OnFailure = append(b.Step.OnFailure, onFailure)
	return b
}

// Build builds the workflow step
func (b *WorkflowStepBuilder) Build() *WorkflowStep {
	return b.Step
}

// ClassificationBuilder builds classifications
type ClassificationBuilder struct {
	// Classification is the classification being built
	Classification *Classification
}

// NewClassificationBuilder creates a new classification builder
func NewClassificationBuilder() *ClassificationBuilder {
	return &ClassificationBuilder{
		Classification: &Classification{
			Custom: make(map[string]string),
		},
	}
}

// SetCVE sets the CVE identifier
func (b *ClassificationBuilder) SetCVE(cve string) *ClassificationBuilder {
	b.Classification.CVE = cve
	return b
}

// SetCWE sets the CWE identifier
func (b *ClassificationBuilder) SetCWE(cwe string) *ClassificationBuilder {
	b.Classification.CWE = cwe
	return b
}

// SetCVSS sets the CVSS score
func (b *ClassificationBuilder) SetCVSS(cvss string) *ClassificationBuilder {
	b.Classification.CVSS = cvss
	return b
}

// SetOWASP sets the OWASP category
func (b *ClassificationBuilder) SetOWASP(owasp string) *ClassificationBuilder {
	b.Classification.OWASP = owasp
	return b
}

// SetWASC sets the WASC category
func (b *ClassificationBuilder) SetWASC(wasc string) *ClassificationBuilder {
	b.Classification.WASC = wasc
	return b
}

// SetPCI sets the PCI DSS requirement
func (b *ClassificationBuilder) SetPCI(pci string) *ClassificationBuilder {
	b.Classification.PCI = pci
	return b
}

// SetHIPAA sets the HIPAA requirement
func (b *ClassificationBuilder) SetHIPAA(hipaa string) *ClassificationBuilder {
	b.Classification.HIPAA = hipaa
	return b
}

// SetGDPR sets the GDPR article
func (b *ClassificationBuilder) SetGDPR(gdpr string) *ClassificationBuilder {
	b.Classification.GDPR = gdpr
	return b
}

// SetCustom sets a custom classification
func (b *ClassificationBuilder) SetCustom(key, value string) *ClassificationBuilder {
	b.Classification.Custom[key] = value
	return b
}

// Build builds the classification
func (b *ClassificationBuilder) Build() *Classification {
	return b.Classification
}

// TemplateConverter converts templates between formats
type TemplateConverter struct{}

// NewTemplateConverter creates a new template converter
func NewTemplateConverter() *TemplateConverter {
	return &TemplateConverter{}
}

// ConvertToYAML converts a template to YAML
func (c *TemplateConverter) ConvertToYAML(template *Template) ([]byte, error) {
	// Marshal template to JSON
	jsonData, err := json.Marshal(template)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal template to JSON: %w", err)
	}
	
	// Convert JSON to YAML
	yamlData, err := jsonToYAML(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JSON to YAML: %w", err)
	}
	
	return yamlData, nil
}

// ConvertFromYAML converts a template from YAML
func (c *TemplateConverter) ConvertFromYAML(yamlData []byte) (*Template, error) {
	// Convert YAML to JSON
	jsonData, err := yamlToJSON(yamlData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}
	
	// Unmarshal JSON to template
	var template Template
	if err := json.Unmarshal(jsonData, &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template from JSON: %w", err)
	}
	
	return &template, nil
}

// jsonToYAML converts JSON to YAML
func jsonToYAML(jsonData []byte) ([]byte, error) {
	// This is a placeholder for the actual implementation
	// A real implementation would use a YAML library
	return nil, fmt.Errorf("YAML conversion not implemented")
}

// yamlToJSON converts YAML to JSON
func yamlToJSON(yamlData []byte) ([]byte, error) {
	// This is a placeholder for the actual implementation
	// A real implementation would use a YAML library
	return nil, fmt.Errorf("YAML conversion not implemented")
}

// Import the required packages
// These are placeholders for the actual imports
var ioutil = struct {
	ReadFile  func(string) ([]byte, error)
	WriteFile func(string, []byte, os.FileMode) error
}{
	ReadFile:  func(string) ([]byte, error) { return nil, nil },
	WriteFile: func(string, []byte, os.FileMode) error { return nil },
}

var os = struct {
	FileMode int
}{
	FileMode: 0,
}

var filepath = struct {
	Join  func(string, string) string
	Glob  func(string) ([]string, error)
}{
	Join: func(string, string) string { return "" },
	Glob: func(string) ([]string, error) { return nil, nil },
}
