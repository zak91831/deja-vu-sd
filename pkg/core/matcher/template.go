package matcher

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// TemplateMatcherConfig represents the configuration for a template matcher
type TemplateMatcherConfig struct {
	// Type is the matcher type
	Type MatcherType `json:"type"`
	
	// Part is the part to match
	Part MatchPart `json:"part,omitempty"`
	
	// Condition is the condition for matching
	Condition MatcherCondition `json:"condition,omitempty"`
	
	// Negate inverts the match result
	Negate bool `json:"negate,omitempty"`
	
	// CaseSensitive determines whether matching is case-sensitive
	CaseSensitive bool `json:"case_sensitive,omitempty"`
	
	// Patterns are the patterns to match
	Patterns []string `json:"patterns,omitempty"`
	
	// Regex are the regex patterns to match
	Regex []string `json:"regex,omitempty"`
	
	// Binary are the binary patterns to match
	Binary []string `json:"binary,omitempty"`
	
	// DSL is the DSL expression
	DSL string `json:"dsl,omitempty"`
	
	// Status are the status codes to match
	Status []int `json:"status,omitempty"`
	
	// Size are the sizes to match
	Size []int `json:"size,omitempty"`
	
	// Words are the words to match
	Words []string `json:"words,omitempty"`
	
	// Headers are the headers to match
	Headers map[string]string `json:"headers,omitempty"`
	
	// Fuzzy are the fuzzy patterns to match
	Fuzzy []string `json:"fuzzy,omitempty"`
	
	// FuzzyThreshold is the fuzzy matching threshold
	FuzzyThreshold float64 `json:"fuzzy_threshold,omitempty"`
	
	// Matchers are the sub-matchers for a group
	Matchers []*TemplateMatcherConfig `json:"matchers,omitempty"`
	
	// Steps are the steps for a multi-step matcher
	Steps []*TemplateMatcherStep `json:"steps,omitempty"`
}

// TemplateMatcherStep represents a step in a multi-step matcher configuration
type TemplateMatcherStep struct {
	// Name is the step name
	Name string `json:"name"`
	
	// Matcher is the matcher configuration for this step
	Matcher *TemplateMatcherConfig `json:"matcher"`
	
	// Condition is the condition for this step
	Condition MatcherCondition `json:"condition,omitempty"`
	
	// NextStep is the next step to execute if this step matches
	NextStep string `json:"next_step,omitempty"`
	
	// ElseStep is the next step to execute if this step doesn't match
	ElseStep string `json:"else_step,omitempty"`
}

// TemplateMatcher creates matchers from template configurations
type TemplateMatcher struct {
	// Config is the template matcher configuration
	Config *TemplateMatcherConfig
	
	// Factory is the matcher factory
	Factory *MatcherFactory
	
	// Matcher is the created matcher
	Matcher Matcher
}

// NewTemplateMatcher creates a new template matcher
func NewTemplateMatcher(config *TemplateMatcherConfig) (*TemplateMatcher, error) {
	factory := NewMatcherFactory()
	
	matcher, err := createMatcherFromConfig(config, factory)
	if err != nil {
		return nil, err
	}
	
	return &TemplateMatcher{
		Config:  config,
		Factory: factory,
		Matcher: matcher,
	}, nil
}

// Match checks if the data matches
func (m *TemplateMatcher) Match(data []byte) bool {
	return m.Matcher.Match(data)
}

// MatchWithOptions checks if the data matches with options
func (m *TemplateMatcher) MatchWithOptions(data []byte, options *MatchOptions) bool {
	return m.Matcher.MatchWithOptions(data, options)
}

// Type returns the matcher type
func (m *TemplateMatcher) Type() MatcherType {
	return m.Matcher.Type()
}

// createMatcherFromConfig creates a matcher from a template configuration
func createMatcherFromConfig(config *TemplateMatcherConfig, factory *MatcherFactory) (Matcher, error) {
	// Create match options
	options := NewMatchOptions()
	options.CaseSensitive = config.CaseSensitive
	options.Negate = config.Negate
	
	if config.Part != "" {
		options.Part = config.Part
	}
	
	// Create matcher based on type
	switch config.Type {
	case StringMatcher:
		return factory.CreateMatcher(StringMatcher, config.Patterns, options)
		
	case RegexMatcher:
		patterns := config.Patterns
		if len(config.Regex) > 0 {
			patterns = config.Regex
		}
		return factory.CreateMatcher(RegexMatcher, patterns, options)
		
	case BinaryMatcher:
		patterns := config.Patterns
		if len(config.Binary) > 0 {
			patterns = config.Binary
		}
		return factory.CreateMatcher(BinaryMatcher, patterns, options)
		
	case DSLMatcher:
		if config.DSL == "" {
			return nil, fmt.Errorf("DSL matcher requires a DSL expression")
		}
		return factory.CreateMatcher(DSLMatcher, []string{config.DSL}, options)
		
	case FuzzyMatcher:
		patterns := config.Patterns
		if len(config.Fuzzy) > 0 {
			patterns = config.Fuzzy
		}
		matcher, err := factory.CreateMatcher(FuzzyMatcher, patterns, options)
		if err != nil {
			return nil, err
		}
		
		// Set threshold if specified
		if config.FuzzyThreshold > 0 {
			fuzzyMatcher := matcher.(*FuzzyMatcher)
			fuzzyMatcher.Threshold = config.FuzzyThreshold
		}
		
		return matcher, nil
		
	case StatusMatcher:
		return factory.CreateStatusMatcher(config.Status, options)
		
	case SizeMatcher:
		return factory.CreateSizeMatcher(config.Size, options)
		
	case WordsMatcher:
		return factory.CreateMatcher(StringMatcher, config.Words, options)
		
	case HeaderMatcher:
		// Convert map[string]string to map[string][]string
		headers := make(map[string][]string)
		for name, value := range config.Headers {
			headers[name] = []string{value}
		}
		return factory.CreateHeaderMatcher(headers, options)
		
	case "group":
		// Create a matcher group
		condition := config.Condition
		if condition == "" {
			condition = ConditionAND
		}
		
		group := factory.CreateMatcherGroup(condition, options)
		
		// Add sub-matchers
		for _, subConfig := range config.Matchers {
			subMatcher, err := createMatcherFromConfig(subConfig, factory)
			if err != nil {
				return nil, err
			}
			
			group.AddMatcher(subMatcher)
		}
		
		return group, nil
		
	case "multi-step":
		// Create a multi-step matcher
		multiStep := factory.CreateMultiStepMatcher(options)
		
		// Add steps
		for _, stepConfig := range config.Steps {
			stepMatcher, err := createMatcherFromConfig(stepConfig.Matcher, factory)
			if err != nil {
				return nil, err
			}
			
			condition := stepConfig.Condition
			if condition == "" {
				condition = ConditionAND
			}
			
			multiStep.AddStep(stepConfig.Name, stepMatcher, condition, stepConfig.NextStep, stepConfig.ElseStep)
		}
		
		return multiStep, nil
		
	default:
		return nil, fmt.Errorf("unsupported matcher type: %s", config.Type)
	}
}

// ParseMatcherConfig parses a matcher configuration from JSON
func ParseMatcherConfig(jsonData []byte) (*TemplateMatcherConfig, error) {
	var config TemplateMatcherConfig
	err := json.Unmarshal(jsonData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse matcher config: %w", err)
	}
	
	return &config, nil
}

// MatcherValidator validates matchers
type MatcherValidator struct{}

// NewMatcherValidator creates a new matcher validator
func NewMatcherValidator() *MatcherValidator {
	return &MatcherValidator{}
}

// ValidateConfig validates a matcher configuration
func (v *MatcherValidator) ValidateConfig(config *TemplateMatcherConfig) error {
	if config == nil {
		return fmt.Errorf("matcher config is nil")
	}
	
	// Validate matcher type
	if config.Type == "" {
		return fmt.Errorf("matcher type is required")
	}
	
	// Validate based on type
	switch config.Type {
	case StringMatcher:
		if len(config.Patterns) == 0 {
			return fmt.Errorf("string matcher requires patterns")
		}
		
	case RegexMatcher:
		patterns := config.Patterns
		if len(config.Regex) > 0 {
			patterns = config.Regex
		}
		
		if len(patterns) == 0 {
			return fmt.Errorf("regex matcher requires patterns")
		}
		
		// Validate regex patterns
		for _, pattern := range patterns {
			_, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
			}
		}
		
	case BinaryMatcher:
		patterns := config.Patterns
		if len(config.Binary) > 0 {
			patterns = config.Binary
		}
		
		if len(patterns) == 0 {
			return fmt.Errorf("binary matcher requires patterns")
		}
		
		// Validate binary patterns
		for _, pattern := range patterns {
			// Remove 0x prefix if present
			if strings.HasPrefix(pattern, "0x") {
				pattern = pattern[2:]
			}
			
			// Check if valid hex
			for _, c := range pattern {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					return fmt.Errorf("invalid binary pattern '%s': not a valid hex string", pattern)
				}
			}
		}
		
	case DSLMatcher:
		if config.DSL == "" {
			return fmt.Errorf("DSL matcher requires a DSL expression")
		}
		
	case FuzzyMatcher:
		patterns := config.Patterns
		if len(config.Fuzzy) > 0 {
			patterns = config.Fuzzy
		}
		
		if len(patterns) == 0 {
			return fmt.Errorf("fuzzy matcher requires patterns")
		}
		
		if config.FuzzyThreshold < 0 || config.FuzzyThreshold > 1.0 {
			return fmt.Errorf("fuzzy threshold must be between 0 and 1")
		}
		
	case StatusMatcher:
		if len(config.Status) == 0 {
			return fmt.Errorf("status matcher requires status codes")
		}
		
		// Validate status codes
		for _, code := range config.Status {
			if code < 100 || code >= 600 {
				return fmt.Errorf("invalid status code: %d", code)
			}
		}
		
	case SizeMatcher:
		if len(config.Size) == 0 {
			return fmt.Errorf("size matcher requires sizes")
		}
		
		// Validate sizes
		for _, size := range config.Size {
			if size < 0 {
				return fmt.Errorf("invalid size: %d", size)
			}
		}
		
	case WordsMatcher:
		if len(config.Words) == 0 {
			return fmt.Errorf("words matcher requires words")
		}
		
	case HeaderMatcher:
		if len(config.Headers) == 0 {
			return fmt.Errorf("header matcher requires headers")
		}
		
	case "group":
		if len(config.Matchers) == 0 {
			return fmt.Errorf("group matcher requires sub-matchers")
		}
		
		// Validate sub-matchers
		for _, subConfig := range config.Matchers {
			if err := v.ValidateConfig(subConfig); err != nil {
				return err
			}
		}
		
	case "multi-step":
		if len(config.Steps) == 0 {
			return fmt.Errorf("multi-step matcher requires steps")
		}
		
		// Validate steps
		stepNames := make(map[string]bool)
		for _, step := range config.Steps {
			if step.Name == "" {
				return fmt.Errorf("step name is required")
			}
			
			if stepNames[step.Name] {
				return fmt.Errorf("duplicate step name: %s", step.Name)
			}
			
			stepNames[step.Name] = true
			
			if step.Matcher == nil {
				return fmt.Errorf("step matcher is required")
			}
			
			if err := v.ValidateConfig(step.Matcher); err != nil {
				return err
			}
		}
		
		// Validate step references
		for _, step := range config.Steps {
			if step.NextStep != "" && !stepNames[step.NextStep] {
				return fmt.Errorf("next step '%s' not found", step.NextStep)
			}
			
			if step.ElseStep != "" && !stepNames[step.ElseStep] {
				return fmt.Errorf("else step '%s' not found", step.ElseStep)
			}
		}
		
	default:
		return fmt.Errorf("unsupported matcher type: %s", config.Type)
	}
	
	return nil
}

// ValidateMatcher validates a matcher
func (v *MatcherValidator) ValidateMatcher(matcher Matcher) error {
	if matcher == nil {
		return fmt.Errorf("matcher is nil")
	}
	
	// Validate based on type
	switch matcher.Type() {
	case RegexMatcher:
		regexMatcher, ok := matcher.(*RegexMatcher)
		if !ok {
			return fmt.Errorf("invalid regex matcher type")
		}
		
		if len(regexMatcher.Patterns) == 0 {
			return fmt.Errorf("regex matcher requires patterns")
		}
		
	case BinaryMatcher:
		binaryMatcher, ok := matcher.(*BinaryMatcher)
		if !ok {
			return fmt.Errorf("invalid binary matcher type")
		}
		
		if len(binaryMatcher.Patterns) == 0 {
			return fmt.Errorf("binary matcher requires patterns")
		}
		
	case "group":
		groupMatcher, ok := matcher.(*MatcherGroup)
		if !ok {
			return fmt.Errorf("invalid group matcher type")
		}
		
		if len(groupMatcher.Matchers) == 0 {
			return fmt.Errorf("group matcher requires sub-matchers")
		}
		
		// Validate sub-matchers
		for _, subMatcher := range groupMatcher.Matchers {
			if err := v.ValidateMatcher(subMatcher); err != nil {
				return err
			}
		}
		
	case "multi-step":
		multiStepMatcher, ok := matcher.(*MultiStepMatcher)
		if !ok {
			return fmt.Errorf("invalid multi-step matcher type")
		}
		
		if len(multiStepMatcher.Steps) == 0 {
			return fmt.Errorf("multi-step matcher requires steps")
		}
		
		// Validate steps
		stepNames := make(map[string]bool)
		for _, step := range multiStepMatcher.Steps {
			if step.Name == "" {
				return fmt.Errorf("step name is required")
			}
			
			if stepNames[step.Name] {
				return fmt.Errorf("duplicate step name: %s", step.Name)
			}
			
			stepNames[step.Name] = true
			
			if step.Matcher == nil {
				return fmt.Errorf("step matcher is required")
			}
			
			if err := v.ValidateMatcher(step.Matcher); err != nil {
				return err
			}
		}
		
		// Validate step references
		for _, step := range multiStepMatcher.Steps {
			if step.NextStep != "" && !stepNames[step.NextStep] {
				return fmt.Errorf("next step '%s' not found", step.NextStep)
			}
			
			if step.ElseStep != "" && !stepNames[step.ElseStep] {
				return fmt.Errorf("else step '%s' not found", step.ElseStep)
			}
		}
	}
	
	return nil
}
