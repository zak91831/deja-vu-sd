package extractor

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// CorrelationExtractor correlates multiple extractors
type CorrelationExtractor struct {
	// Extractors are the extractors to correlate
	Extractors []Extractor
	
	// Options are the extract options
	Options *ExtractOptions
	
	// CorrelationMode defines how to correlate results
	CorrelationMode string
}

// CorrelationMode defines how to correlate results
const (
	// CorrelationModeAND requires all extractors to extract data
	CorrelationModeAND = "and"
	
	// CorrelationModeOR requires any extractor to extract data
	CorrelationModeOR = "or"
	
	// CorrelationModeChain chains extractors (output of one is input to next)
	CorrelationModeChain = "chain"
	
	// CorrelationModeZip zips results from all extractors
	CorrelationModeZip = "zip"
)

// NewCorrelationExtractor creates a new correlation extractor
func NewCorrelationExtractor(extractors []Extractor, mode string, options *ExtractOptions) *CorrelationExtractor {
	if options == nil {
		options = NewExtractOptions()
	}
	
	if mode == "" {
		mode = CorrelationModeAND
	}
	
	return &CorrelationExtractor{
		Extractors:     extractors,
		Options:        options,
		CorrelationMode: mode,
	}
}

// Extract correlates data from multiple extractors
func (e *CorrelationExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions correlates data from multiple extractors with options
func (e *CorrelationExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	if options == nil {
		options = e.Options
	}
	
	if len(e.Extractors) == 0 {
		return nil, fmt.Errorf("no extractors to correlate")
	}
	
	switch e.CorrelationMode {
	case CorrelationModeAND:
		return e.correlateAND(data, options)
	case CorrelationModeOR:
		return e.correlateOR(data, options)
	case CorrelationModeChain:
		return e.correlateChain(data, options)
	case CorrelationModeZip:
		return e.correlateZip(data, options)
	default:
		return e.correlateAND(data, options)
	}
}

// correlateAND correlates data using AND mode
func (e *CorrelationExtractor) correlateAND(data []byte, options *ExtractOptions) ([]string, error) {
	var results []string
	
	// Extract data from all extractors
	for _, extractor := range e.Extractors {
		extracted, err := extractor.ExtractWithOptions(data, options)
		if err != nil {
			return nil, err
		}
		
		if len(extracted) == 0 {
			// If any extractor returns no results, return empty
			return nil, nil
		}
		
		// For the first extractor, initialize results
		if len(results) == 0 {
			results = extracted
		} else {
			// For subsequent extractors, keep only common results
			common := make([]string, 0)
			for _, r1 := range results {
				for _, r2 := range extracted {
					if r1 == r2 {
						common = append(common, r1)
						break
					}
				}
			}
			results = common
		}
	}
	
	return results, nil
}

// correlateOR correlates data using OR mode
func (e *CorrelationExtractor) correlateOR(data []byte, options *ExtractOptions) ([]string, error) {
	var results []string
	
	// Extract data from all extractors
	for _, extractor := range e.Extractors {
		extracted, err := extractor.ExtractWithOptions(data, options)
		if err != nil {
			continue
		}
		
		// Add unique results
		for _, r := range extracted {
			unique := true
			for _, existing := range results {
				if r == existing {
					unique = false
					break
				}
			}
			
			if unique {
				results = append(results, r)
			}
		}
	}
	
	return results, nil
}

// correlateChain correlates data using Chain mode
func (e *CorrelationExtractor) correlateChain(data []byte, options *ExtractOptions) ([]string, error) {
	if len(e.Extractors) == 0 {
		return nil, nil
	}
	
	// Start with the first extractor
	results, err := e.Extractors[0].ExtractWithOptions(data, options)
	if err != nil {
		return nil, err
	}
	
	// Chain through remaining extractors
	for i := 1; i < len(e.Extractors); i++ {
		var chainedResults []string
		
		for _, r := range results {
			extracted, err := e.Extractors[i].ExtractWithOptions([]byte(r), options)
			if err != nil {
				continue
			}
			
			chainedResults = append(chainedResults, extracted...)
		}
		
		results = chainedResults
	}
	
	return results, nil
}

// correlateZip correlates data using Zip mode
func (e *CorrelationExtractor) correlateZip(data []byte, options *ExtractOptions) ([]string, error) {
	var allResults [][]string
	
	// Extract data from all extractors
	for _, extractor := range e.Extractors {
		extracted, err := extractor.ExtractWithOptions(data, options)
		if err != nil {
			// Use empty slice for failed extractors
			extracted = []string{}
		}
		
		allResults = append(allResults, extracted)
	}
	
	// Zip results
	var results []string
	maxLen := 0
	
	// Find maximum length
	for _, r := range allResults {
		if len(r) > maxLen {
			maxLen = len(r)
		}
	}
	
	// Zip results
	for i := 0; i < maxLen; i++ {
		var zipped string
		
		for j, r := range allResults {
			if i < len(r) {
				if j > 0 {
					zipped += ":"
				}
				zipped += r[i]
			} else {
				if j > 0 {
					zipped += ":"
				}
				zipped += ""
			}
		}
		
		results = append(results, zipped)
	}
	
	return results, nil
}

// Type returns the extractor type
func (e *CorrelationExtractor) Type() ExtractorType {
	return "correlation"
}

// TransformExtractor transforms extracted data
type TransformExtractor struct {
	// Extractor is the base extractor
	Extractor Extractor
	
	// Transformers are the transformers to apply
	Transformers []Transformer
	
	// Options are the extract options
	Options *ExtractOptions
}

// Transformer transforms extracted data
type Transformer interface {
	// Transform transforms data
	Transform(data []string) ([]string, error)
}

// NewTransformExtractor creates a new transform extractor
func NewTransformExtractor(extractor Extractor, transformers []Transformer, options *ExtractOptions) *TransformExtractor {
	if options == nil {
		options = NewExtractOptions()
	}
	
	return &TransformExtractor{
		Extractor:    extractor,
		Transformers: transformers,
		Options:      options,
	}
}

// Extract extracts and transforms data
func (e *TransformExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions extracts and transforms data with options
func (e *TransformExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	if options == nil {
		options = e.Options
	}
	
	// Extract data
	results, err := e.Extractor.ExtractWithOptions(data, options)
	if err != nil {
		return nil, err
	}
	
	// Apply transformers
	for _, transformer := range e.Transformers {
		results, err = transformer.Transform(results)
		if err != nil {
			return nil, err
		}
	}
	
	return results, nil
}

// Type returns the extractor type
func (e *TransformExtractor) Type() ExtractorType {
	return e.Extractor.Type()
}

// RegexTransformer transforms data using regex
type RegexTransformer struct {
	// Pattern is the regex pattern
	Pattern *regexp.Regexp
	
	// Replacement is the replacement string
	Replacement string
}

// NewRegexTransformer creates a new regex transformer
func NewRegexTransformer(pattern string, replacement string) (*RegexTransformer, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex pattern '%s': %w", pattern, err)
	}
	
	return &RegexTransformer{
		Pattern:     re,
		Replacement: replacement,
	}, nil
}

// Transform transforms data using regex
func (t *RegexTransformer) Transform(data []string) ([]string, error) {
	var results []string
	
	for _, d := range data {
		transformed := t.Pattern.ReplaceAllString(d, t.Replacement)
		results = append(results, transformed)
	}
	
	return results, nil
}

// CaseTransformer transforms data case
type CaseTransformer struct {
	// Mode is the case transformation mode
	Mode string
}

// Case transformation modes
const (
	// CaseLower transforms to lowercase
	CaseLower = "lower"
	
	// CaseUpper transforms to uppercase
	CaseUpper = "upper"
	
	// CaseTitle transforms to title case
	CaseTitle = "title"
)

// NewCaseTransformer creates a new case transformer
func NewCaseTransformer(mode string) *CaseTransformer {
	return &CaseTransformer{
		Mode: mode,
	}
}

// Transform transforms data case
func (t *CaseTransformer) Transform(data []string) ([]string, error) {
	var results []string
	
	for _, d := range data {
		var transformed string
		
		switch t.Mode {
		case CaseLower:
			transformed = strings.ToLower(d)
		case CaseUpper:
			transformed = strings.ToUpper(d)
		case CaseTitle:
			transformed = strings.Title(d)
		default:
			transformed = d
		}
		
		results = append(results, transformed)
	}
	
	return results, nil
}

// TrimTransformer trims data
type TrimTransformer struct {
	// Chars are the characters to trim
	Chars string
}

// NewTrimTransformer creates a new trim transformer
func NewTrimTransformer(chars string) *TrimTransformer {
	return &TrimTransformer{
		Chars: chars,
	}
}

// Transform trims data
func (t *TrimTransformer) Transform(data []string) ([]string, error) {
	var results []string
	
	for _, d := range data {
		var transformed string
		
		if t.Chars == "" {
			transformed = strings.TrimSpace(d)
		} else {
			transformed = strings.Trim(d, t.Chars)
		}
		
		results = append(results, transformed)
	}
	
	return results, nil
}

// TemplateExtractorConfig represents the configuration for a template extractor
type TemplateExtractorConfig struct {
	// Type is the extractor type
	Type ExtractorType `json:"type"`
	
	// Part is the part to extract from
	Part ExtractPart `json:"part,omitempty"`
	
	// Regex are the regex patterns to extract
	Regex []string `json:"regex,omitempty"`
	
	// RegexGroup is the regex group to extract
	RegexGroup int `json:"regex_group,omitempty"`
	
	// JSON are the JSON paths to extract
	JSON []string `json:"json,omitempty"`
	
	// XML are the XML paths to extract
	XML []string `json:"xml,omitempty"`
	
	// HTML are the HTML selectors to extract
	HTML []string `json:"html,omitempty"`
	
	// Attribute is the HTML attribute to extract
	Attribute string `json:"attribute,omitempty"`
	
	// Headers are the header names to extract
	Headers []string `json:"headers,omitempty"`
	
	// Cookies are the cookie names to extract
	Cookies []string `json:"cookies,omitempty"`
	
	// DSL are the DSL expressions to extract
	DSL []string `json:"dsl,omitempty"`
	
	// Extractors are the sub-extractors for correlation
	Extractors []*TemplateExtractorConfig `json:"extractors,omitempty"`
	
	// CorrelationMode is the correlation mode
	CorrelationMode string `json:"correlation_mode,omitempty"`
	
	// Transformers are the transformers to apply
	Transformers []*TemplateTransformerConfig `json:"transformers,omitempty"`
}

// TemplateTransformerConfig represents the configuration for a template transformer
type TemplateTransformerConfig struct {
	// Type is the transformer type
	Type string `json:"type"`
	
	// Regex is the regex pattern for regex transformer
	Regex string `json:"regex,omitempty"`
	
	// Replacement is the replacement string for regex transformer
	Replacement string `json:"replacement,omitempty"`
	
	// Case is the case transformation mode
	Case string `json:"case,omitempty"`
	
	// Trim are the characters to trim
	Trim string `json:"trim,omitempty"`
}

// TemplateExtractor creates extractors from template configurations
type TemplateExtractor struct {
	// Config is the template extractor configuration
	Config *TemplateExtractorConfig
	
	// Factory is the extractor factory
	Factory *ExtractorFactory
	
	// Extractor is the created extractor
	Extractor Extractor
}

// NewTemplateExtractor creates a new template extractor
func NewTemplateExtractor(config *TemplateExtractorConfig) (*TemplateExtractor, error) {
	factory := NewExtractorFactory()
	
	extractor, err := createExtractorFromConfig(config, factory)
	if err != nil {
		return nil, err
	}
	
	return &TemplateExtractor{
		Config:   config,
		Factory:  factory,
		Extractor: extractor,
	}, nil
}

// Extract extracts data
func (e *TemplateExtractor) Extract(data []byte) ([]string, error) {
	return e.Extractor.Extract(data)
}

// ExtractWithOptions extracts data with options
func (e *TemplateExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	return e.Extractor.ExtractWithOptions(data, options)
}

// Type returns the extractor type
func (e *TemplateExtractor) Type() ExtractorType {
	return e.Extractor.Type()
}

// createExtractorFromConfig creates an extractor from a template configuration
func createExtractorFromConfig(config *TemplateExtractorConfig, factory *ExtractorFactory) (Extractor, error) {
	// Create extract options
	options := NewExtractOptions()
	
	if config.Part != "" {
		options.Part = config.Part
	}
	
	if config.Attribute != "" {
		options.Internal["attribute"] = config.Attribute
	}
	
	// Create extractor based on type
	var extractor Extractor
	var err error
	
	switch config.Type {
	case RegexExtractor:
		group := 0
		if config.RegexGroup > 0 {
			group = config.RegexGroup
		}
		extractor, err = factory.CreateRegexExtractor(config.Regex, group, options)
		
	case JSONExtractor:
		extractor, err = factory.CreateJSONExtractor(config.JSON, options)
		
	case XMLExtractor:
		extractor, err = factory.CreateXMLExtractor(config.XML, options)
		
	case HTMLExtractor:
		extractor, err = factory.CreateHTMLExtractor(config.HTML, options)
		
	case HeaderExtractor:
		extractor = factory.CreateHeaderExtractor(config.Headers, options)
		
	case CookieExtractor:
		extractor = factory.CreateCookieExtractor(config.Cookies, options)
		
	case DSLExtractor:
		extractor, err = factory.CreateDSLExtractor(config.DSL, options)
		
	case "correlation":
		if len(config.Extractors) == 0 {
			return nil, fmt.Errorf("correlation extractor requires sub-extractors")
		}
		
		// Create sub-extractors
		extractors := make([]Extractor, 0, len(config.Extractors))
		for _, subConfig := range config.Extractors {
			subExtractor, err := createExtractorFromConfig(subConfig, factory)
			if err != nil {
				return nil, err
			}
			
			extractors = append(extractors, subExtractor)
		}
		
		// Create correlation extractor
		extractor = NewCorrelationExtractor(extractors, config.CorrelationMode, options)
		
	default:
		return nil, fmt.Errorf("unsupported extractor type: %s", config.Type)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Apply transformers if specified
	if len(config.Transformers) > 0 {
		transformers, err := createTransformersFromConfig(config.Transformers)
		if err != nil {
			return nil, err
		}
		
		extractor = NewTransformExtractor(extractor, transformers, options)
	}
	
	return extractor, nil
}

// createTransformersFromConfig creates transformers from template configurations
func createTransformersFromConfig(configs []*TemplateTransformerConfig) ([]Transformer, error) {
	transformers := make([]Transformer, 0, len(configs))
	
	for _, config := range configs {
		var transformer Transformer
		var err error
		
		switch config.Type {
		case "regex":
			transformer, err = NewRegexTransformer(config.Regex, config.Replacement)
			
		case "case":
			transformer = NewCaseTransformer(config.Case)
			
		case "trim":
			transformer = NewTrimTransformer(config.Trim)
			
		default:
			return nil, fmt.Errorf("unsupported transformer type: %s", config.Type)
		}
		
		if err != nil {
			return nil, err
		}
		
		transformers = append(transformers, transformer)
	}
	
	return transformers, nil
}

// ParseExtractorConfig parses an extractor configuration from JSON
func ParseExtractorConfig(jsonData []byte) (*TemplateExtractorConfig, error) {
	var config TemplateExtractorConfig
	err := json.Unmarshal(jsonData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse extractor config: %w", err)
	}
	
	return &config, nil
}

// Import the required packages
// These are placeholders for the actual imports
var strings = struct {
	ToLower    func(string) string
	ToUpper    func(string) string
	Title      func(string) string
	TrimSpace  func(string) string
	Trim       func(string, string) string
}{
	ToLower:    func(s string) string { return s },
	ToUpper:    func(s string) string { return s },
	Title:      func(s string) string { return s },
	TrimSpace:  func(s string) string { return s },
	Trim:       func(s, cutset string) string { return s },
}
