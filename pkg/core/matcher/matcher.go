package matcher

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// MatcherType defines the type of matcher
type MatcherType string

const (
	// StringMatcher matches strings
	StringMatcher MatcherType = "string"
	
	// RegexMatcher matches regular expressions
	RegexMatcher MatcherType = "regex"
	
	// BinaryMatcher matches binary data
	BinaryMatcher MatcherType = "binary"
	
	// DSLMatcher matches using a domain-specific language
	DSLMatcher MatcherType = "dsl"
	
	// FuzzyMatcher matches with fuzzy logic
	FuzzyMatcher MatcherType = "fuzzy"
	
	// HashMatcher matches cryptographic hashes
	HashMatcher MatcherType = "hash"
	
	// StatusMatcher matches HTTP status codes
	StatusMatcher MatcherType = "status"
	
	// SizeMatcher matches response sizes
	SizeMatcher MatcherType = "size"
	
	// TimeMatcher matches response times
	TimeMatcher MatcherType = "time"
	
	// WordsMatcher matches words
	WordsMatcher MatcherType = "words"
	
	// HeaderMatcher matches HTTP headers
	HeaderMatcher MatcherType = "header"
)

// MatcherCondition defines the condition for matching
type MatcherCondition string

const (
	// ConditionAND requires all matchers to match
	ConditionAND MatcherCondition = "and"
	
	// ConditionOR requires any matcher to match
	ConditionOR MatcherCondition = "or"
	
	// ConditionNOT requires no matcher to match
	ConditionNOT MatcherCondition = "not"
)

// MatchPart defines which part of the response to match
type MatchPart string

const (
	// BodyPart matches the response body
	BodyPart MatchPart = "body"
	
	// HeaderPart matches the response headers
	HeaderPart MatchPart = "header"
	
	// AllPart matches the entire response
	AllPart MatchPart = "all"
	
	// StatusPart matches the response status
	StatusPart MatchPart = "status"
)

// Matcher defines the interface for all matchers
type Matcher interface {
	// Match checks if the data matches
	Match(data []byte) bool
	
	// MatchWithOptions checks if the data matches with options
	MatchWithOptions(data []byte, options *MatchOptions) bool
	
	// Type returns the matcher type
	Type() MatcherType
}

// MatchOptions contains options for matching
type MatchOptions struct {
	// CaseSensitive determines whether matching is case-sensitive
	CaseSensitive bool
	
	// MatchAll determines whether all patterns must match
	MatchAll bool
	
	// Negate inverts the match result
	Negate bool
	
	// Part specifies which part of the response to match
	Part MatchPart
	
	// Headers contains the response headers for header matching
	Headers map[string][]string
	
	// StatusCode contains the response status code for status matching
	StatusCode int
	
	// ResponseTime contains the response time for time matching
	ResponseTime int
	
	// ResponseSize contains the response size for size matching
	ResponseSize int
}

// NewMatchOptions creates new match options with defaults
func NewMatchOptions() *MatchOptions {
	return &MatchOptions{
		CaseSensitive: true,
		MatchAll:      true,
		Negate:        false,
		Part:          BodyPart,
		Headers:       make(map[string][]string),
	}
}

// StringMatcher matches strings
type StringMatcher struct {
	// Patterns are the string patterns to match
	Patterns []string
	
	// Options are the match options
	Options *MatchOptions
}

// NewStringMatcher creates a new string matcher
func NewStringMatcher(patterns []string, options *MatchOptions) *StringMatcher {
	if options == nil {
		options = NewMatchOptions()
	}
	
	return &StringMatcher{
		Patterns: patterns,
		Options:  options,
	}
}

// Match checks if the data matches any pattern
func (m *StringMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the data matches any pattern with options
func (m *StringMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = m.Options
	}
	
	// Get the data to match based on the part
	var matchData []byte
	switch options.Part {
	case BodyPart:
		matchData = data
	case HeaderPart:
		// Convert headers to string for matching
		var headerStr strings.Builder
		for name, values := range options.Headers {
			for _, value := range values {
				headerStr.WriteString(name)
				headerStr.WriteString(": ")
				headerStr.WriteString(value)
				headerStr.WriteString("\n")
			}
		}
		matchData = []byte(headerStr.String())
	case StatusPart:
		// Convert status code to string for matching
		matchData = []byte(fmt.Sprintf("%d", options.StatusCode))
	case AllPart:
		// Combine all parts for matching
		var allStr strings.Builder
		allStr.WriteString(fmt.Sprintf("%d\n", options.StatusCode))
		for name, values := range options.Headers {
			for _, value := range values {
				allStr.WriteString(name)
				allStr.WriteString(": ")
				allStr.WriteString(value)
				allStr.WriteString("\n")
			}
		}
		allStr.Write(data)
		matchData = []byte(allStr.String())
	default:
		matchData = data
	}
	
	// Convert to string for easier handling
	dataStr := string(matchData)
	if !options.CaseSensitive {
		dataStr = strings.ToLower(dataStr)
	}
	
	// Check each pattern
	matches := 0
	for _, pattern := range m.Patterns {
		if !options.CaseSensitive {
			pattern = strings.ToLower(pattern)
		}
		
		if strings.Contains(dataStr, pattern) {
			matches++
			if !options.MatchAll {
				break // One match is enough for OR condition
			}
		} else if options.MatchAll {
			// If any pattern doesn't match in AND condition, return false
			return options.Negate
		}
	}
	
	// Determine result based on match count and options
	var result bool
	if options.MatchAll {
		result = matches == len(m.Patterns)
	} else {
		result = matches > 0
	}
	
	// Apply negation if needed
	if options.Negate {
		return !result
	}
	
	return result
}

// Type returns the matcher type
func (m *StringMatcher) Type() MatcherType {
	return StringMatcher
}

// RegexMatcher matches regular expressions
type RegexMatcher struct {
	// Patterns are the regex patterns to match
	Patterns []*regexp.Regexp
	
	// RawPatterns are the raw regex pattern strings
	RawPatterns []string
	
	// Options are the match options
	Options *MatchOptions
}

// NewRegexMatcher creates a new regex matcher
func NewRegexMatcher(patterns []string, options *MatchOptions) (*RegexMatcher, error) {
	if options == nil {
		options = NewMatchOptions()
	}
	
	compiledPatterns := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		var re *regexp.Regexp
		var err error
		
		if options.CaseSensitive {
			re, err = regexp.Compile(pattern)
		} else {
			re, err = regexp.Compile("(?i)" + pattern)
		}
		
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex pattern '%s': %w", pattern, err)
		}
		
		compiledPatterns = append(compiledPatterns, re)
	}
	
	return &RegexMatcher{
		Patterns:    compiledPatterns,
		RawPatterns: patterns,
		Options:     options,
	}, nil
}

// Match checks if the data matches any pattern
func (m *RegexMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the data matches any pattern with options
func (m *RegexMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = m.Options
	}
	
	// Get the data to match based on the part
	var matchData []byte
	switch options.Part {
	case BodyPart:
		matchData = data
	case HeaderPart:
		// Convert headers to string for matching
		var headerStr strings.Builder
		for name, values := range options.Headers {
			for _, value := range values {
				headerStr.WriteString(name)
				headerStr.WriteString(": ")
				headerStr.WriteString(value)
				headerStr.WriteString("\n")
			}
		}
		matchData = []byte(headerStr.String())
	case StatusPart:
		// Convert status code to string for matching
		matchData = []byte(fmt.Sprintf("%d", options.StatusCode))
	case AllPart:
		// Combine all parts for matching
		var allStr strings.Builder
		allStr.WriteString(fmt.Sprintf("%d\n", options.StatusCode))
		for name, values := range options.Headers {
			for _, value := range values {
				allStr.WriteString(name)
				allStr.WriteString(": ")
				allStr.WriteString(value)
				allStr.WriteString("\n")
			}
		}
		allStr.Write(data)
		matchData = []byte(allStr.String())
	default:
		matchData = data
	}
	
	// Check each pattern
	matches := 0
	for _, re := range m.Patterns {
		if re.Match(matchData) {
			matches++
			if !options.MatchAll {
				break // One match is enough for OR condition
			}
		} else if options.MatchAll {
			// If any pattern doesn't match in AND condition, return false
			return options.Negate
		}
	}
	
	// Determine result based on match count and options
	var result bool
	if options.MatchAll {
		result = matches == len(m.Patterns)
	} else {
		result = matches > 0
	}
	
	// Apply negation if needed
	if options.Negate {
		return !result
	}
	
	return result
}

// Type returns the matcher type
func (m *RegexMatcher) Type() MatcherType {
	return RegexMatcher
}

// BinaryMatcher matches binary data
type BinaryMatcher struct {
	// Patterns are the binary patterns to match
	Patterns [][]byte
	
	// RawPatterns are the raw binary pattern strings
	RawPatterns []string
	
	// Options are the match options
	Options *MatchOptions
}

// NewBinaryMatcher creates a new binary matcher
func NewBinaryMatcher(patterns []string, options *MatchOptions) (*BinaryMatcher, error) {
	if options == nil {
		options = NewMatchOptions()
	}
	
	binaryPatterns := make([][]byte, 0, len(patterns))
	for _, pattern := range patterns {
		// Handle hex format (0x...)
		if strings.HasPrefix(pattern, "0x") {
			pattern = pattern[2:]
		}
		
		// Decode hex string
		decoded, err := hex.DecodeString(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to decode binary pattern '%s': %w", pattern, err)
		}
		
		binaryPatterns = append(binaryPatterns, decoded)
	}
	
	return &BinaryMatcher{
		Patterns:    binaryPatterns,
		RawPatterns: patterns,
		Options:     options,
	}, nil
}

// Match checks if the data matches any pattern
func (m *BinaryMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the data matches any pattern with options
func (m *BinaryMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = m.Options
	}
	
	// Binary matcher only works on body data
	matchData := data
	
	// Check each pattern
	matches := 0
	for _, pattern := range m.Patterns {
		if bytes.Contains(matchData, pattern) {
			matches++
			if !options.MatchAll {
				break // One match is enough for OR condition
			}
		} else if options.MatchAll {
			// If any pattern doesn't match in AND condition, return false
			return options.Negate
		}
	}
	
	// Determine result based on match count and options
	var result bool
	if options.MatchAll {
		result = matches == len(m.Patterns)
	} else {
		result = matches > 0
	}
	
	// Apply negation if needed
	if options.Negate {
		return !result
	}
	
	return result
}

// Type returns the matcher type
func (m *BinaryMatcher) Type() MatcherType {
	return BinaryMatcher
}

// StatusMatcher matches HTTP status codes
type StatusMatcher struct {
	// Codes are the status codes to match
	Codes []int
	
	// Options are the match options
	Options *MatchOptions
}

// NewStatusMatcher creates a new status matcher
func NewStatusMatcher(codes []int, options *MatchOptions) *StatusMatcher {
	if options == nil {
		options = NewMatchOptions()
	}
	
	return &StatusMatcher{
		Codes:   codes,
		Options: options,
	}
}

// Match checks if the status code matches any code
func (m *StatusMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the status code matches any code with options
func (m *StatusMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = m.Options
	}
	
	statusCode := options.StatusCode
	
	// Check each code
	matches := 0
	for _, code := range m.Codes {
		if statusCode == code {
			matches++
			if !options.MatchAll {
				break // One match is enough for OR condition
			}
		} else if options.MatchAll {
			// If any code doesn't match in AND condition, return false
			return options.Negate
		}
	}
	
	// Determine result based on match count and options
	var result bool
	if options.MatchAll {
		result = matches == len(m.Codes)
	} else {
		result = matches > 0
	}
	
	// Apply negation if needed
	if options.Negate {
		return !result
	}
	
	return result
}

// Type returns the matcher type
func (m *StatusMatcher) Type() MatcherType {
	return StatusMatcher
}

// SizeMatcher matches response sizes
type SizeMatcher struct {
	// Sizes are the sizes to match
	Sizes []int
	
	// Options are the match options
	Options *MatchOptions
}

// NewSizeMatcher creates a new size matcher
func NewSizeMatcher(sizes []int, options *MatchOptions) *SizeMatcher {
	if options == nil {
		options = NewMatchOptions()
	}
	
	return &SizeMatcher{
		Sizes:   sizes,
		Options: options,
	}
}

// Match checks if the response size matches any size
func (m *SizeMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the response size matches any size with options
func (m *SizeMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = m.Options
	}
	
	var size int
	if options.ResponseSize > 0 {
		size = options.ResponseSize
	} else {
		size = len(data)
	}
	
	// Check each size
	matches := 0
	for _, targetSize := range m.Sizes {
		if size == targetSize {
			matches++
			if !options.MatchAll {
				break // One match is enough for OR condition
			}
		} else if options.MatchAll {
			// If any size doesn't match in AND condition, return false
			return options.Negate
		}
	}
	
	// Determine result based on match count and options
	var result bool
	if options.MatchAll {
		result = matches == len(m.Sizes)
	} else {
		result = matches > 0
	}
	
	// Apply negation if needed
	if options.Negate {
		return !result
	}
	
	return result
}

// Type returns the matcher type
func (m *SizeMatcher) Type() MatcherType {
	return SizeMatcher
}

// HeaderMatcher matches HTTP headers
type HeaderMatcher struct {
	// Headers are the headers to match (name -> values)
	Headers map[string][]string
	
	// Options are the match options
	Options *MatchOptions
}

// NewHeaderMatcher creates a new header matcher
func NewHeaderMatcher(headers map[string][]string, options *MatchOptions) *HeaderMatcher {
	if options == nil {
		options = NewMatchOptions()
	}
	
	return &HeaderMatcher{
		Headers: headers,
		Options: options,
	}
}

// Match checks if the headers match
func (m *HeaderMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the headers match with options
func (m *HeaderMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = m.Options
	}
	
	responseHeaders := options.Headers
	
	// Check each header
	matches := 0
	headerCount := 0
	
	for name, values := range m.Headers {
		headerCount++
		
		// Get response header values
		responseValues, exists := responseHeaders[name]
		if !exists {
			if options.MatchAll {
				// If any header doesn't exist in AND condition, return false
				return options.Negate
			}
			continue
		}
		
		// Check if any value matches
		valueMatches := false
		for _, value := range values {
			for _, responseValue := range responseValues {
				if options.CaseSensitive {
					if value == responseValue {
						valueMatches = true
						break
					}
				} else {
					if strings.EqualFold(value, responseValue) {
						valueMatches = true
						break
					}
				}
			}
			
			if valueMatches {
				break
			}
		}
		
		if valueMatches {
			matches++
			if !options.MatchAll {
				break // One match is enough for OR condition
			}
		} else if options.MatchAll {
			// If any header value doesn't match in AND condition, return false
			return options.Negate
		}
	}
	
	// Determine result based on match count and options
	var result bool
	if options.MatchAll {
		result = matches == headerCount
	} else {
		result = matches > 0
	}
	
	// Apply negation if needed
	if options.Negate {
		return !result
	}
	
	return result
}

// Type returns the matcher type
func (m *HeaderMatcher) Type() MatcherType {
	return HeaderMatcher
}

// FuzzyMatcher matches with fuzzy logic
type FuzzyMatcher struct {
	// Patterns are the patterns to match
	Patterns []string
	
	// Threshold is the similarity threshold (0.0-1.0)
	Threshold float64
	
	// Options are the match options
	Options *MatchOptions
}

// NewFuzzyMatcher creates a new fuzzy matcher
func NewFuzzyMatcher(patterns []string, threshold float64, options *MatchOptions) *FuzzyMatcher {
	if options == nil {
		options = NewMatchOptions()
	}
	
	if threshold <= 0 || threshold > 1.0 {
		threshold = 0.8 // Default threshold
	}
	
	return &FuzzyMatcher{
		Patterns:  patterns,
		Threshold: threshold,
		Options:   options,
	}
}

// Match checks if the data fuzzy matches any pattern
func (m *FuzzyMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the data fuzzy matches any pattern with options
func (m *FuzzyMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = m.Options
	}
	
	// Get the data to match based on the part
	var matchData []byte
	switch options.Part {
	case BodyPart:
		matchData = data
	case HeaderPart:
		// Convert headers to string for matching
		var headerStr strings.Builder
		for name, values := range options.Headers {
			for _, value := range values {
				headerStr.WriteString(name)
				headerStr.WriteString(": ")
				headerStr.WriteString(value)
				headerStr.WriteString("\n")
			}
		}
		matchData = []byte(headerStr.String())
	case StatusPart:
		// Convert status code to string for matching
		matchData = []byte(fmt.Sprintf("%d", options.StatusCode))
	case AllPart:
		// Combine all parts for matching
		var allStr strings.Builder
		allStr.WriteString(fmt.Sprintf("%d\n", options.StatusCode))
		for name, values := range options.Headers {
			for _, value := range values {
				allStr.WriteString(name)
				allStr.WriteString(": ")
				allStr.WriteString(value)
				allStr.WriteString("\n")
			}
		}
		allStr.Write(data)
		matchData = []byte(allStr.String())
	default:
		matchData = data
	}
	
	// Convert to string for easier handling
	dataStr := string(matchData)
	if !options.CaseSensitive {
		dataStr = strings.ToLower(dataStr)
	}
	
	// Check each pattern
	matches := 0
	for _, pattern := range m.Patterns {
		if !options.CaseSensitive {
			pattern = strings.ToLower(pattern)
		}
		
		similarity := calculateSimilarity(dataStr, pattern)
		if similarity >= m.Threshold {
			matches++
			if !options.MatchAll {
				break // One match is enough for OR condition
			}
		} else if options.MatchAll {
			// If any pattern doesn't match in AND condition, return false
			return options.Negate
		}
	}
	
	// Determine result based on match count and options
	var result bool
	if options.MatchAll {
		result = matches == len(m.Patterns)
	} else {
		result = matches > 0
	}
	
	// Apply negation if needed
	if options.Negate {
		return !result
	}
	
	return result
}

// Type returns the matcher type
func (m *FuzzyMatcher) Type() MatcherType {
	return FuzzyMatcher
}

// calculateSimilarity calculates the similarity between two strings
// using Levenshtein distance
func calculateSimilarity(s1, s2 string) float64 {
	// Simple implementation of Levenshtein distance
	// A more efficient implementation would be used in production
	
	// If either string is empty, return 0
	if len(s1) == 0 || len(s2) == 0 {
		return 0
	}
	
	// If strings are identical, return 1
	if s1 == s2 {
		return 1
	}
	
	// Create distance matrix
	d := make([][]int, len(s1)+1)
	for i := range d {
		d[i] = make([]int, len(s2)+1)
	}
	
	// Initialize first row and column
	for i := 0; i <= len(s1); i++ {
		d[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		d[0][j] = j
	}
	
	// Fill the matrix
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			
			d[i][j] = min(
				d[i-1][j]+1,      // deletion
				d[i][j-1]+1,      // insertion
				d[i-1][j-1]+cost, // substitution
			)
		}
	}
	
	// Calculate similarity
	maxLen := max(len(s1), len(s2))
	distance := d[len(s1)][len(s2)]
	similarity := 1.0 - float64(distance)/float64(maxLen)
	
	return similarity
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
