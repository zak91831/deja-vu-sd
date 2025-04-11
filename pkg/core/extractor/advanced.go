package extractor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

// JSONExtractor extracts data using JSON paths
type JSONExtractor struct {
	// Paths are the JSON paths to extract
	Paths []string
	
	// Options are the extract options
	Options *ExtractOptions
}

// NewJSONExtractor creates a new JSON extractor
func NewJSONExtractor(paths []string, options *ExtractOptions) (*JSONExtractor, error) {
	if options == nil {
		options = NewExtractOptions()
	}
	
	return &JSONExtractor{
		Paths:   paths,
		Options: options,
	}, nil
}

// Extract extracts data using JSON paths
func (e *JSONExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions extracts data using JSON paths with options
func (e *JSONExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	if options == nil {
		options = e.Options
	}
	
	// Get the data to extract from based on the part
	var extractData []byte
	switch options.Part {
	case BodyPart:
		extractData = data
	default:
		// JSON extraction only works on body data
		extractData = data
	}
	
	// Validate JSON
	if !json.Valid(extractData) {
		return nil, fmt.Errorf("invalid JSON data")
	}
	
	// Extract using JSON paths
	var results []string
	for _, path := range e.Paths {
		result := gjson.GetBytes(extractData, path)
		
		if result.Exists() {
			switch result.Type {
			case gjson.JSON:
				// For objects and arrays, add the JSON string
				results = append(results, result.Raw)
			default:
				// For primitive types, add the string value
				results = append(results, result.String())
			}
		}
	}
	
	return results, nil
}

// Type returns the extractor type
func (e *JSONExtractor) Type() ExtractorType {
	return JSONExtractor
}

// XMLExtractor extracts data using XML paths
type XMLExtractor struct {
	// Paths are the XML paths to extract
	Paths []string
	
	// Options are the extract options
	Options *ExtractOptions
}

// NewXMLExtractor creates a new XML extractor
func NewXMLExtractor(paths []string, options *ExtractOptions) (*XMLExtractor, error) {
	if options == nil {
		options = NewExtractOptions()
	}
	
	return &XMLExtractor{
		Paths:   paths,
		Options: options,
	}, nil
}

// Extract extracts data using XML paths
func (e *XMLExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions extracts data using XML paths with options
func (e *XMLExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	if options == nil {
		options = e.Options
	}
	
	// Get the data to extract from based on the part
	var extractData []byte
	switch options.Part {
	case BodyPart:
		extractData = data
	default:
		// XML extraction only works on body data
		extractData = data
	}
	
	// Parse XML
	doc, err := xmlquery.Parse(strings.NewReader(string(extractData)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	
	// Extract using XML paths
	var results []string
	for _, path := range e.Paths {
		nodes, err := xmlquery.QueryAll(doc, path)
		if err != nil {
			continue
		}
		
		for _, node := range nodes {
			results = append(results, node.InnerText())
		}
	}
	
	return results, nil
}

// Type returns the extractor type
func (e *XMLExtractor) Type() ExtractorType {
	return XMLExtractor
}

// HTMLExtractor extracts data using HTML selectors
type HTMLExtractor struct {
	// Selectors are the HTML selectors to extract
	Selectors []string
	
	// Options are the extract options
	Options *ExtractOptions
	
	// Attribute is the attribute to extract (empty for text content)
	Attribute string
}

// NewHTMLExtractor creates a new HTML extractor
func NewHTMLExtractor(selectors []string, options *ExtractOptions) (*HTMLExtractor, error) {
	if options == nil {
		options = NewExtractOptions()
	}
	
	attribute := ""
	if attr, ok := options.Internal["attribute"].(string); ok {
		attribute = attr
	}
	
	return &HTMLExtractor{
		Selectors: selectors,
		Options:   options,
		Attribute: attribute,
	}, nil
}

// Extract extracts data using HTML selectors
func (e *HTMLExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions extracts data using HTML selectors with options
func (e *HTMLExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
	if options == nil {
		options = e.Options
	}
	
	// Get the data to extract from based on the part
	var extractData []byte
	switch options.Part {
	case BodyPart:
		extractData = data
	default:
		// HTML extraction only works on body data
		extractData = data
	}
	
	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(extractData)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}
	
	// Extract using HTML selectors
	var results []string
	for _, selector := range e.Selectors {
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			if e.Attribute != "" {
				// Extract attribute value
				if val, exists := s.Attr(e.Attribute); exists {
					results = append(results, val)
				}
			} else {
				// Extract text content
				results = append(results, s.Text())
			}
		})
	}
	
	return results, nil
}

// Type returns the extractor type
func (e *HTMLExtractor) Type() ExtractorType {
	return HTMLExtractor
}

// DSLExtractor extracts data using a domain-specific language
type DSLExtractor struct {
	// Expressions are the DSL expressions to extract
	Expressions []string
	
	// Options are the extract options
	Options *ExtractOptions
	
	// parser is the DSL parser
	parser *DSLParser
}

// NewDSLExtractor creates a new DSL extractor
func NewDSLExtractor(expressions []string, options *ExtractOptions) (*DSLExtractor, error) {
	if options == nil {
		options = NewExtractOptions()
	}
	
	parser, err := NewDSLParser(expressions)
	if err != nil {
		return nil, err
	}
	
	return &DSLExtractor{
		Expressions: expressions,
		Options:     options,
		parser:      parser,
	}, nil
}

// Extract extracts data using DSL expressions
func (e *DSLExtractor) Extract(data []byte) ([]string, error) {
	return e.ExtractWithOptions(data, e.Options)
}

// ExtractWithOptions extracts data using DSL expressions with options
func (e *DSLExtractor) ExtractWithOptions(data []byte, options *ExtractOptions) ([]string, error) {
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
	
	// Extract using DSL expressions
	return e.parser.Extract(extractData, options)
}

// Type returns the extractor type
func (e *DSLExtractor) Type() ExtractorType {
	return DSLExtractor
}

// DSLParser parses and evaluates DSL expressions
type DSLParser struct {
	// Expressions are the DSL expressions
	Expressions []string
}

// NewDSLParser creates a new DSL parser
func NewDSLParser(expressions []string) (*DSLParser, error) {
	return &DSLParser{
		Expressions: expressions,
	}, nil
}

// Extract extracts data using DSL expressions
func (p *DSLParser) Extract(data []byte, options *ExtractOptions) ([]string, error) {
	// Simple extraction for demonstration
	// A real implementation would use a proper DSL parser
	
	var results []string
	dataStr := string(data)
	
	for _, expr := range p.Expressions {
		// Simple between extraction for demonstration
		if strings.HasPrefix(expr, "between(") && strings.HasSuffix(expr, ")") {
			// Extract parameters
			params := expr[8 : len(expr)-1]
			parts := strings.Split(params, ",")
			
			if len(parts) == 2 {
				start := strings.TrimSpace(parts[0])
				end := strings.TrimSpace(parts[1])
				
				// Remove quotes if present
				if strings.HasPrefix(start, "\"") && strings.HasSuffix(start, "\"") {
					start = start[1 : len(start)-1]
				}
				if strings.HasPrefix(end, "\"") && strings.HasSuffix(end, "\"") {
					end = end[1 : len(end)-1]
				}
				
				// Find all occurrences
				startIndex := 0
				for {
					startPos := strings.Index(dataStr[startIndex:], start)
					if startPos == -1 {
						break
					}
					
					startPos += startIndex + len(start)
					endPos := strings.Index(dataStr[startPos:], end)
					if endPos == -1 {
						break
					}
					
					results = append(results, dataStr[startPos:startPos+endPos])
					startIndex = startPos + endPos + len(end)
				}
			}
		}
	}
	
	return results, nil
}

// Import the required packages
// These are placeholders for the actual imports
type xmlquery struct{}

func (x *xmlquery) Parse(r *strings.Reader) (interface{}, error) {
	return nil, fmt.Errorf("XML parsing not implemented")
}

func (x *xmlquery) QueryAll(doc interface{}, path string) ([]xmlNode, error) {
	return nil, fmt.Errorf("XML query not implemented")
}

type xmlNode struct{}

func (n *xmlNode) InnerText() string {
	return ""
}

type goquery struct{}

func (g *goquery) NewDocumentFromReader(r *strings.Reader) (interface{}, error) {
	return nil, fmt.Errorf("HTML parsing not implemented")
}

type goquerySel struct{}

func (s *goquerySel) Find(selector string) *goquerySel {
	return nil
}

func (s *goquerySel) Each(f func(int, *goquerySel)) {
}

func (s *goquerySel) Text() string {
	return ""
}

func (s *goquerySel) Attr(name string) (string, bool) {
	return "", false
}
