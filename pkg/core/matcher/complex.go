package matcher

import (
	"fmt"
	"strings"
)

// MatcherGroup represents a group of matchers with a condition
type MatcherGroup struct {
	// Matchers are the matchers in the group
	Matchers []Matcher
	
	// Condition is the condition for matching
	Condition MatcherCondition
	
	// Options are the match options
	Options *MatchOptions
}

// NewMatcherGroup creates a new matcher group
func NewMatcherGroup(condition MatcherCondition, options *MatchOptions) *MatcherGroup {
	if options == nil {
		options = NewMatchOptions()
	}
	
	return &MatcherGroup{
		Matchers:  make([]Matcher, 0),
		Condition: condition,
		Options:   options,
	}
}

// AddMatcher adds a matcher to the group
func (g *MatcherGroup) AddMatcher(matcher Matcher) {
	g.Matchers = append(g.Matchers, matcher)
}

// Match checks if the data matches according to the condition
func (g *MatcherGroup) Match(data []byte) bool {
	return g.MatchWithOptions(data, g.Options)
}

// MatchWithOptions checks if the data matches according to the condition with options
func (g *MatcherGroup) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = g.Options
	}
	
	if len(g.Matchers) == 0 {
		return false
	}
	
	switch g.Condition {
	case ConditionAND:
		// All matchers must match
		for _, matcher := range g.Matchers {
			if !matcher.MatchWithOptions(data, options) {
				return false
			}
		}
		return true
		
	case ConditionOR:
		// Any matcher must match
		for _, matcher := range g.Matchers {
			if matcher.MatchWithOptions(data, options) {
				return true
			}
		}
		return false
		
	case ConditionNOT:
		// No matcher must match
		for _, matcher := range g.Matchers {
			if matcher.MatchWithOptions(data, options) {
				return false
			}
		}
		return true
		
	default:
		// Default to AND
		for _, matcher := range g.Matchers {
			if !matcher.MatchWithOptions(data, options) {
				return false
			}
		}
		return true
	}
}

// Type returns the matcher type
func (g *MatcherGroup) Type() MatcherType {
	return "group"
}

// DSLMatcher matches using a domain-specific language
type DSLMatcher struct {
	// Expression is the DSL expression
	Expression string
	
	// Options are the match options
	Options *MatchOptions
	
	// parser is the DSL parser
	parser *DSLParser
}

// NewDSLMatcher creates a new DSL matcher
func NewDSLMatcher(expression string, options *MatchOptions) (*DSLMatcher, error) {
	if options == nil {
		options = NewMatchOptions()
	}
	
	parser, err := NewDSLParser(expression)
	if err != nil {
		return nil, err
	}
	
	return &DSLMatcher{
		Expression: expression,
		Options:    options,
		parser:     parser,
	}, nil
}

// Match checks if the data matches the DSL expression
func (m *DSLMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the data matches the DSL expression with options
func (m *DSLMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
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
	
	// Evaluate the DSL expression
	result, err := m.parser.Evaluate(matchData, options)
	if err != nil {
		// If evaluation fails, consider it a non-match
		return false
	}
	
	// Apply negation if needed
	if options.Negate {
		return !result
	}
	
	return result
}

// Type returns the matcher type
func (m *DSLMatcher) Type() MatcherType {
	return DSLMatcher
}

// DSLParser parses and evaluates DSL expressions
type DSLParser struct {
	// Expression is the DSL expression
	Expression string
	
	// tokens are the parsed tokens
	tokens []string
}

// NewDSLParser creates a new DSL parser
func NewDSLParser(expression string) (*DSLParser, error) {
	// Simple tokenization for demonstration
	// A real implementation would use a proper parser
	tokens := strings.Fields(expression)
	
	return &DSLParser{
		Expression: expression,
		tokens:     tokens,
	}, nil
}

// Evaluate evaluates the DSL expression against data
func (p *DSLParser) Evaluate(data []byte, options *MatchOptions) (bool, error) {
	// Simple evaluation for demonstration
	// A real implementation would use a proper evaluator
	
	// If no tokens, return false
	if len(p.tokens) == 0 {
		return false, nil
	}
	
	// Convert data to string for easier handling
	dataStr := string(data)
	if !options.CaseSensitive {
		dataStr = strings.ToLower(dataStr)
	}
	
	// Simple contains check for demonstration
	// A real implementation would support complex expressions
	for _, token := range p.tokens {
		if !options.CaseSensitive {
			token = strings.ToLower(token)
		}
		
		if strings.Contains(dataStr, token) {
			return true, nil
		}
	}
	
	return false, nil
}

// MultiStepMatcher represents a multi-step matcher
type MultiStepMatcher struct {
	// Steps are the matcher steps
	Steps []*MatcherStep
	
	// Options are the match options
	Options *MatchOptions
}

// MatcherStep represents a step in a multi-step matcher
type MatcherStep struct {
	// Matcher is the matcher for this step
	Matcher Matcher
	
	// Name is the step name
	Name string
	
	// Condition is the condition for this step
	Condition MatcherCondition
	
	// NextStep is the next step to execute if this step matches
	NextStep string
	
	// ElseStep is the next step to execute if this step doesn't match
	ElseStep string
}

// NewMultiStepMatcher creates a new multi-step matcher
func NewMultiStepMatcher(options *MatchOptions) *MultiStepMatcher {
	if options == nil {
		options = NewMatchOptions()
	}
	
	return &MultiStepMatcher{
		Steps:   make([]*MatcherStep, 0),
		Options: options,
	}
}

// AddStep adds a step to the multi-step matcher
func (m *MultiStepMatcher) AddStep(name string, matcher Matcher, condition MatcherCondition, nextStep, elseStep string) {
	step := &MatcherStep{
		Name:      name,
		Matcher:   matcher,
		Condition: condition,
		NextStep:  nextStep,
		ElseStep:  elseStep,
	}
	
	m.Steps = append(m.Steps, step)
}

// Match checks if the data matches according to the multi-step logic
func (m *MultiStepMatcher) Match(data []byte) bool {
	return m.MatchWithOptions(data, m.Options)
}

// MatchWithOptions checks if the data matches according to the multi-step logic with options
func (m *MultiStepMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	if options == nil {
		options = m.Options
	}
	
	if len(m.Steps) == 0 {
		return false
	}
	
	// Start with the first step
	currentStep := m.Steps[0]
	
	// Execute steps until we reach a terminal step
	for currentStep != nil {
		// Match the current step
		matched := currentStep.Matcher.MatchWithOptions(data, options)
		
		// Determine next step
		var nextStepName string
		if matched {
			nextStepName = currentStep.NextStep
		} else {
			nextStepName = currentStep.ElseStep
		}
		
		// If no next step, return the match result
		if nextStepName == "" {
			return matched
		}
		
		// Find the next step
		currentStep = nil
		for _, step := range m.Steps {
			if step.Name == nextStepName {
				currentStep = step
				break
			}
		}
		
		// If next step not found, return false
		if currentStep == nil {
			return false
		}
	}
	
	return false
}

// Type returns the matcher type
func (m *MultiStepMatcher) Type() MatcherType {
	return "multi-step"
}

// MatcherFactory creates matchers
type MatcherFactory struct{}

// NewMatcherFactory creates a new matcher factory
func NewMatcherFactory() *MatcherFactory {
	return &MatcherFactory{}
}

// CreateMatcher creates a matcher of the specified type
func (f *MatcherFactory) CreateMatcher(matcherType MatcherType, patterns []string, options *MatchOptions) (Matcher, error) {
	switch matcherType {
	case StringMatcher:
		return NewStringMatcher(patterns, options), nil
		
	case RegexMatcher:
		return NewRegexMatcher(patterns, options)
		
	case BinaryMatcher:
		return NewBinaryMatcher(patterns, options)
		
	case DSLMatcher:
		if len(patterns) == 0 {
			return nil, fmt.Errorf("DSL matcher requires an expression")
		}
		return NewDSLMatcher(patterns[0], options)
		
	case FuzzyMatcher:
		return NewFuzzyMatcher(patterns, 0.8, options), nil
		
	default:
		return nil, fmt.Errorf("unsupported matcher type: %s", matcherType)
	}
}

// CreateStatusMatcher creates a status matcher
func (f *MatcherFactory) CreateStatusMatcher(codes []int, options *MatchOptions) (Matcher, error) {
	return NewStatusMatcher(codes, options), nil
}

// CreateSizeMatcher creates a size matcher
func (f *MatcherFactory) CreateSizeMatcher(sizes []int, options *MatchOptions) (Matcher, error) {
	return NewSizeMatcher(sizes, options), nil
}

// CreateHeaderMatcher creates a header matcher
func (f *MatcherFactory) CreateHeaderMatcher(headers map[string][]string, options *MatchOptions) (Matcher, error) {
	return NewHeaderMatcher(headers, options), nil
}

// CreateMatcherGroup creates a matcher group
func (f *MatcherFactory) CreateMatcherGroup(condition MatcherCondition, options *MatchOptions) *MatcherGroup {
	return NewMatcherGroup(condition, options)
}

// CreateMultiStepMatcher creates a multi-step matcher
func (f *MatcherFactory) CreateMultiStepMatcher(options *MatchOptions) *MultiStepMatcher {
	return NewMultiStepMatcher(options)
}
