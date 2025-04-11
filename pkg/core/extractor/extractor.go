package extractor

import (
	"fmt"
	"regexp"
)

// ExtractorType defines the type of extractor
type ExtractorType string

const (
	// RegexExtractor extracts using regular expressions
	RegexExtractor ExtractorType = "regex"
	
	// JSONExtractor extracts using JSON paths
	JSONExtractor ExtractorType = "json"
	
	// XMLExtractor extracts using XML paths
	XMLExtractor ExtractorType = "xml"
	
	// HTMLExtractor extracts using HTML selectors
	HTMLExtractor ExtractorType = "html"
	
	// HeaderExtractor extracts from HTTP headers
	HeaderExtractor ExtractorType = "header"
	
	// CookieExtractor extracts from HTTP cookies
	CookieExtractor ExtractorType = "cookie"
	
	// DSLExtractor extracts using a domain-specific language
	DSLExtractor ExtractorType = "dsl"
)

// ExtractPart defines which part of the response to extract from
type ExtractPart string

const (
	// BodyPart extracts from the response body
	BodyPart ExtractPart = "body"
	
	// HeaderPart extracts from the response headers
	HeaderPart ExtractPart = "header"
	
	// AllPart extracts from the entire response
	AllPart ExtractPart = "all"
)

// Extractor defines the interface for all extractors
type Extractor interface {
	// Extract extracts data from the input
	Extract(data []byte) ([]string, error)
	
	// ExtractWithOptions extracts data from the input with options
	ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error)
	
	// Type returns the extractor type
	Type() ExtractorType
}

// ExtractOptions contains options for extraction
type ExtractOptions struct {
	// Part specifies which part of the response to extract from
	Part ExtractPart
	
	// Headers contains the response headers for header extraction
	Headers map[string][]string
	
	// Cookies contains the response cookies for cookie extraction
	Cookies map[string]string
	
	// Internal is used for internal options specific to each extractor
	Internal map[string]interface{}
}

// NewExtractOptions creates new extract options with defaults
func NewExtractOptions() *ExtractOptions {
	return &ExtractOptions{
		Part:     BodyPart,
		Headers:  make(map[string][]string),
		Cookies:  make(map[string]string),
		Internal: make(map[string]interface{}),
	}
}

// RegexExtractor extracts data using regular expressions
type RegexExtractor struct {
	// Patterns are the regex patterns to extract
	Patterns []*regexp.Regexp
	
	// RawPatterns are the raw regex pattern strings
	RawPatterns []string
	
	// Options are the extract options
	Options *ExtractOptions
	
	// Group is the regex group to extract (0 = full match)
	Group int
}

// NewRegexExtractor creates a new regex extractor
func NewRegexExtractor(patterns []string, group int, options *ExtractOptions) (*RegexExtractor, error) {
	if options == nil {
		options = NewExtractOptions()
	}
	
	compiledPatterns := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex pattern '%s': %w", pattern, err)
		}
		
		compiledPatterns = append(compiledPatterns, re)
	}
	
	return &RegexExtractor{
		Patterns:    compiledPatterns,
		RawPatterns: patterns,
		Options:     options,
		Group:       group,
	}, nil
}

// Extract extracts data using regex patterns
func (e *RegexExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions extracts data using regex patterns with options
func (e *RegexExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	if options == nil {
		options = e.Options
	}
	
	// Get the data to extract from based on the part
	var extractData []byte
	switch options.Part {
	case BodyPart:
		extractData = data
	case HeaderPart:
		// Convert headers to string for extraction
		var headerStr string
		for name, values := range options.Headers {
			for _, value := range values {
				headerStr += name + ": " + value + "\n"
			}
		}
		extractData = []byte(headerStr)
	case AllPart:
		// Combine all parts for extraction
		var allStr string
		for name, values := range options.Headers {
			for _, value := range values {
				allStr += name + ": " + value + "\n"
			}
		}
		allStr += string(data)
		extractData = []byte(allStr)
	default:
		extractData = data
	}
	
	// Extract using regex patterns
	var results []string
	for _, re := range e.Patterns {
		matches := re.FindAllSubmatch(extractData, -1)
		for _, match := range matches {
			if e.Group >= 0 && e.Group < len(match) {
				results = append(results, string(match[e.Group]))
			}
		}
	}
	
	return results, nil
}

// Type returns the extractor type
func (e *RegexExtractor) Type() ExtractorType {
	return RegexExtractor
}

// HeaderExtractor extracts data from HTTP headers
type HeaderExtractor struct {
	// Names are the header names to extract
	Names []string
	
	// Options are the extract options
	Options *ExtractOptions
}

// NewHeaderExtractor creates a new header extractor
func NewHeaderExtractor(names []string, options *ExtractOptions) *HeaderExtractor {
	if options == nil {
		options = NewExtractOptions()
	}
	
	return &HeaderExtractor{
		Names:   names,
		Options: options,
	}
}

// Extract extracts data from headers
func (e *HeaderExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions extracts data from headers with options
func (e *HeaderExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	if options == nil {
		options = e.Options
	}
	
	var results []string
	for _, name := range e.Names {
		values, exists := options.Headers[name]
		if exists {
			results = append(results, values...)
		}
	}
	
	return results, nil
}

// Type returns the extractor type
func (e *HeaderExtractor) Type() ExtractorType {
	return HeaderExtractor
}

// CookieExtractor extracts data from HTTP cookies
type CookieExtractor struct {
	// Names are the cookie names to extract
	Names []string
	
	// Options are the extract options
	Options *ExtractOptions
}

// NewCookieExtractor creates a new cookie extractor
func NewCookieExtractor(names []string, options *ExtractOptions) *CookieExtractor {
	if options == nil {
		options = NewExtractOptions()
	}
	
	return &CookieExtractor{
		Names:   names,
		Options: options,
	}
}

// Extract extracts data from cookies
func (e *CookieExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions extracts data from cookies with options
func (e *CookieExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	if options == nil {
		options = e.Options
	}
	
	var results []string
	for _, name := range e.Names {
		value, exists := options.Cookies[name]
		if exists {
			results = append(results, value)
		}
	}
	
	return results, nil
}

// Type returns the extractor type
func (e *CookieExtractor) Type() ExtractorType {
	return CookieExtractor
}

// ExtractorFactory creates extractors
type ExtractorFactory struct{}

// NewExtractorFactory creates a new extractor factory
func NewExtractorFactory() *ExtractorFactory {
	return &ExtractorFactory{}
}

// CreateRegexExtractor creates a regex extractor
func (f *ExtractorFactory) CreateRegexExtractor(patterns []string, group int, options *ExtractOptions) (Extractor, error) {
	return NewRegexExtractor(patterns, group, options)
}

// CreateHeaderExtractor creates a header extractor
func (f *ExtractorFactory) CreateHeaderExtractor(names []string, options *ExtractOptions) Extractor {
	return NewHeaderExtractor(names, options)
}

// CreateCookieExtractor creates a cookie extractor
func (f *ExtractorFactory) CreateCookieExtractor(names []string, options *ExtractOptions) Extractor {
	return NewCookieExtractor(names, options)
}

// CreateJSONExtractor creates a JSON extractor
func (f *ExtractorFactory) CreateJSONExtractor(paths []string, options *ExtractOptions) (Extractor, error) {
	return NewJSONExtractor(paths, options)
}

// CreateXMLExtractor creates an XML extractor
func (f *ExtractorFactory) CreateXMLExtractor(paths []string, options *ExtractOptions) (Extractor, error) {
	return NewXMLExtractor(paths, options)
}

// CreateHTMLExtractor creates an HTML extractor
func (f *ExtractorFactory) CreateHTMLExtractor(selectors []string, options *ExtractOptions) (Extractor, error) {
	return NewHTMLExtractor(selectors, options)
}

// CreateDSLExtractor creates a DSL extractor
func (f *ExtractorFactory) CreateDSLExtractor(expressions []string, options *ExtractOptions) (Extractor, error) {
	return NewDSLExtractor(expressions, options)
}
