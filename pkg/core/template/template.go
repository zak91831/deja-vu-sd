package template

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template represents a vulnerability scanning template
type Template struct {
	ID          string                 `yaml:"id"`
	Info        TemplateInfo           `yaml:"info"`
	Variables   map[string]interface{} `yaml:"variables,omitempty"`
	Requests    []Request              `yaml:"requests"`
	raw         []byte                 // Raw template content
}

// TemplateInfo contains metadata about the template
type TemplateInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Tags        []string `yaml:"tags"`
}

// Request represents a request to be made as part of the template
type Request struct {
	Method      string                 `yaml:"method"`
	Path        string                 `yaml:"path"`
	Headers     map[string]string      `yaml:"headers,omitempty"`
	Body        string                 `yaml:"body,omitempty"`
	Matchers    []Matcher              `yaml:"matchers,omitempty"`
	Extractors  []Extractor            `yaml:"extractors,omitempty"`
	Variables   map[string]interface{} `yaml:"variables,omitempty"`
}

// Matcher represents a condition to match in the response
type Matcher struct {
	Type    string   `yaml:"type"`
	Part    string   `yaml:"part"`
	Words   []string `yaml:"words,omitempty"`
	Regex   []string `yaml:"regex,omitempty"`
	Status  []int    `yaml:"status,omitempty"`
	Condition string `yaml:"condition,omitempty"`
}

// Extractor represents data to extract from the response
type Extractor struct {
	Type  string   `yaml:"type"`
	Part  string   `yaml:"part"`
	Name  string   `yaml:"name"`
	Regex []string `yaml:"regex,omitempty"`
	JSON  []string `yaml:"json,omitempty"`
}

// TemplateLoader handles loading and parsing templates
type TemplateLoader struct {
	templateDir string
}

// NewTemplateLoader creates a new template loader
func NewTemplateLoader(templateDir string) *TemplateLoader {
	return &TemplateLoader{
		templateDir: templateDir,
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
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Store raw template content
	template.raw = data

	return &template, nil
}

// LoadTemplates loads all templates from the template directory
func (l *TemplateLoader) LoadTemplates() ([]*Template, error) {
	templates := make([]*Template, 0)

	// Find all YAML files in the template directory
	files, err := filepath.Glob(filepath.Join(l.templateDir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to list template files: %w", err)
	}

	// Also check for .yml files
	ymlFiles, err := filepath.Glob(filepath.Join(l.templateDir, "*.yml"))
	if err != nil {
		return nil, fmt.Errorf("failed to list template files: %w", err)
	}

	files = append(files, ymlFiles...)

	// Load each template
	for _, file := range files {
		template, err := l.LoadTemplate(file)
		if err != nil {
			fmt.Printf("Warning: Failed to load template %s: %v\n", file, err)
			continue
		}

		templates = append(templates, template)
	}

	return templates, nil
}

// FilterTemplatesByTags filters templates by tags
func FilterTemplatesByTags(templates []*Template, tags []string) []*Template {
	if len(tags) == 0 {
		return templates
	}

	filtered := make([]*Template, 0)

	for _, template := range templates {
		// Check if template has any of the specified tags
		for _, tag := range tags {
			for _, templateTag := range template.Info.Tags {
				if strings.EqualFold(tag, templateTag) {
					filtered = append(filtered, template)
					break
				}
			}
		}
	}

	return filtered
}

// FilterTemplatesBySeverity filters templates by severity
func FilterTemplatesBySeverity(templates []*Template, severities []string) []*Template {
	if len(severities) == 0 {
		return templates
	}

	filtered := make([]*Template, 0)

	for _, template := range templates {
		// Check if template has the specified severity
		for _, severity := range severities {
			if strings.EqualFold(severity, template.Info.Severity) {
				filtered = append(filtered, template)
				break
			}
		}
	}

	return filtered
}
