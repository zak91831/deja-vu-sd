package detection

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PassiveDetector implements passive vulnerability detection
type PassiveDetector struct {
	// ID is the detector ID
	id string
	
	// Name is the detector name
	name string
	
	// Description is the detector description
	description string
	
	// Capabilities are the detector capabilities
	capabilities *DetectorCapabilities
	
	// Signatures contains vulnerability signatures
	signatures []*VulnerabilitySignature
	
	// Patterns contains detection patterns
	patterns []*DetectionPattern
}

// VulnerabilitySignature represents a vulnerability signature
type VulnerabilitySignature struct {
	// ID is the signature ID
	ID string
	
	// Name is the signature name
	Name string
	
	// Description is the signature description
	Description string
	
	// Category is the vulnerability category
	Category string
	
	// Severity is the vulnerability severity
	Severity string
	
	// CVSS is the CVSS score
	CVSS string
	
	// CWE is the CWE ID
	CWE string
	
	// OWASP is the OWASP category
	OWASP string
	
	// References contains reference URLs
	References []string
	
	// Patterns contains detection patterns
	Patterns []*DetectionPattern
	
	// Remediation contains remediation information
	Remediation *Remediation
}

// DetectionPattern represents a detection pattern
type DetectionPattern struct {
	// Type is the pattern type
	Type string
	
	// Value is the pattern value
	Value string
	
	// Part is the part to match
	Part string
	
	// Regex is the compiled regex pattern
	Regex *regexp.Regexp
	
	// CaseSensitive indicates whether matching is case-sensitive
	CaseSensitive bool
	
	// Negate inverts the match result
	Negate bool
	
	// Weight is the pattern weight
	Weight int
}

// NewPassiveDetector creates a new passive detector
func NewPassiveDetector(id, name, description string) *PassiveDetector {
	return &PassiveDetector{
		id:          id,
		name:        name,
		description: description,
		capabilities: &DetectorCapabilities{
			SupportedProtocols:       []string{"http", "https"},
			SupportedVulnerabilities: []string{},
			RequiresAuthentication:   false,
			IsPassive:                true,
			IsActive:                 false,
		},
		signatures: make([]*VulnerabilitySignature, 0),
		patterns:   make([]*DetectionPattern, 0),
	}
}

// ID returns the detector ID
func (d *PassiveDetector) ID() string {
	return d.id
}

// Name returns the detector name
func (d *PassiveDetector) Name() string {
	return d.name
}

// Description returns the detector description
func (d *PassiveDetector) Description() string {
	return d.description
}

// Capabilities returns the detector capabilities
func (d *PassiveDetector) Capabilities() *DetectorCapabilities {
	return d.capabilities
}

// AddSignature adds a vulnerability signature
func (d *PassiveDetector) AddSignature(signature *VulnerabilitySignature) {
	d.signatures = append(d.signatures, signature)
	
	// Add vulnerability type to supported vulnerabilities
	found := false
	for _, vulnType := range d.capabilities.SupportedVulnerabilities {
		if vulnType == signature.Category {
			found = true
			break
		}
	}
	
	if !found {
		d.capabilities.SupportedVulnerabilities = append(d.capabilities.SupportedVulnerabilities, signature.Category)
	}
}

// AddPattern adds a detection pattern
func (d *PassiveDetector) AddPattern(pattern *DetectionPattern) error {
	// Compile regex pattern if type is regex
	if pattern.Type == "regex" && pattern.Regex == nil {
		var err error
		pattern.Regex, err = regexp.Compile(pattern.Value)
		if err != nil {
			return fmt.Errorf("failed to compile regex pattern: %w", err)
		}
	}
	
	d.patterns = append(d.patterns, pattern)
	return nil
}

// Detect performs vulnerability detection
func (d *PassiveDetector) Detect(target string, options *DetectionOptions) ([]*DetectionResult, error) {
	var results []*DetectionResult
	
	// This is a placeholder for passive detection
	// A real implementation would analyze the target for vulnerabilities
	
	// For each signature, check if target matches any pattern
	for _, signature := range d.signatures {
		for _, pattern := range signature.Patterns {
			// Check if pattern matches target
			if d.matchesPattern(target, pattern) {
				// Create detection result
				result := &DetectionResult{
					ID:         fmt.Sprintf("%s-%s-%d", d.id, signature.ID, time.Now().Unix()),
					DetectorID: d.id,
					Target:     target,
					Vulnerability: &Vulnerability{
						ID:          signature.ID,
						Name:        signature.Name,
						Description: signature.Description,
						Category:    signature.Category,
						Severity:    signature.Severity,
						CVSS:        signature.CVSS,
						CWE:         signature.CWE,
						OWASP:       signature.OWASP,
						References:  signature.References,
						Remediation: signature.Remediation,
					},
					Evidence: &Evidence{
						Type:     "pattern_match",
						Data:     pattern.Value,
						Location: target,
					},
					Timestamp:  time.Now(),
					Confidence: 50, // Base confidence, will be adjusted by confidence calculator
					Severity:   signature.Severity,
					Status:     "detected",
					Metadata:   make(map[string]interface{}),
				}
				
				results = append(results, result)
				break // Move to next signature after first match
			}
		}
	}
	
	return results, nil
}

// matchesPattern checks if a target matches a pattern
func (d *PassiveDetector) matchesPattern(target string, pattern *DetectionPattern) bool {
	// This is a placeholder for pattern matching
	// A real implementation would check if the target matches the pattern
	
	return false
}

// ActiveDetector implements active vulnerability detection
type ActiveDetector struct {
	// ID is the detector ID
	id string
	
	// Name is the detector name
	name string
	
	// Description is the detector description
	description string
	
	// Capabilities are the detector capabilities
	capabilities *DetectorCapabilities
	
	// Tests contains vulnerability tests
	tests []*VulnerabilityTest
	
	// Payloads contains test payloads
	payloads []*TestPayload
}

// VulnerabilityTest represents a vulnerability test
type VulnerabilityTest struct {
	// ID is the test ID
	ID string
	
	// Name is the test name
	Name string
	
	// Description is the test description
	Description string
	
	// Category is the vulnerability category
	Category string
	
	// Severity is the vulnerability severity
	Severity string
	
	// CVSS is the CVSS score
	CVSS string
	
	// CWE is the CWE ID
	CWE string
	
	// OWASP is the OWASP category
	OWASP string
	
	// References contains reference URLs
	References []string
	
	// Payloads contains test payloads
	Payloads []*TestPayload
	
	// Matchers contains response matchers
	Matchers []*TestMatcher
	
	// Remediation contains remediation information
	Remediation *Remediation
}

// TestPayload represents a test payload
type TestPayload struct {
	// Type is the payload type
	Type string
	
	// Value is the payload value
	Value string
	
	// Encoding is the payload encoding
	Encoding string
	
	// Target is the payload target
	Target string
	
	// Method is the HTTP method
	Method string
	
	// Headers are the HTTP headers
	Headers map[string]string
	
	// Parameters are the request parameters
	Parameters map[string]string
}

// TestMatcher represents a response matcher
type TestMatcher struct {
	// Type is the matcher type
	Type string
	
	// Value is the matcher value
	Value string
	
	// Part is the part to match
	Part string
	
	// Regex is the compiled regex pattern
	Regex *regexp.Regexp
	
	// CaseSensitive indicates whether matching is case-sensitive
	CaseSensitive bool
	
	// Negate inverts the match result
	Negate bool
}

// NewActiveDetector creates a new active detector
func NewActiveDetector(id, name, description string) *ActiveDetector {
	return &ActiveDetector{
		id:          id,
		name:        name,
		description: description,
		capabilities: &DetectorCapabilities{
			SupportedProtocols:       []string{"http", "https"},
			SupportedVulnerabilities: []string{},
			RequiresAuthentication:   false,
			IsPassive:                false,
			IsActive:                 true,
		},
		tests:    make([]*VulnerabilityTest, 0),
		payloads: make([]*TestPayload, 0),
	}
}

// ID returns the detector ID
func (d *ActiveDetector) ID() string {
	return d.id
}

// Name returns the detector name
func (d *ActiveDetector) Name() string {
	return d.name
}

// Description returns the detector description
func (d *ActiveDetector) Description() string {
	return d.description
}

// Capabilities returns the detector capabilities
func (d *ActiveDetector) Capabilities() *DetectorCapabilities {
	return d.capabilities
}

// AddTest adds a vulnerability test
func (d *ActiveDetector) AddTest(test *VulnerabilityTest) {
	d.tests = append(d.tests, test)
	
	// Add vulnerability type to supported vulnerabilities
	found := false
	for _, vulnType := range d.capabilities.SupportedVulnerabilities {
		if vulnType == test.Category {
			found = true
			break
		}
	}
	
	if !found {
		d.capabilities.SupportedVulnerabilities = append(d.capabilities.SupportedVulnerabilities, test.Category)
	}
}

// AddPayload adds a test payload
func (d *ActiveDetector) AddPayload(payload *TestPayload) {
	d.payloads = append(d.payloads, payload)
}

// Detect performs vulnerability detection
func (d *ActiveDetector) Detect(target string, options *DetectionOptions) ([]*DetectionResult, error) {
	var results []*DetectionResult
	
	// This is a placeholder for active detection
	// A real implementation would test the target for vulnerabilities
	
	// For each test, send payloads and check responses
	for _, test := range d.tests {
		for _, payload := range test.Payloads {
			// Send payload to target
			response, err := d.sendPayload(target, payload, options)
			if err != nil {
				// Log error but continue with other payloads
				fmt.Printf("Error sending payload: %v\n", err)
				continue
			}
			
			// Check if response matches any matcher
			for _, matcher := range test.Matchers {
				if d.matchesResponse(response, matcher) {
					// Create detection result
					result := &DetectionResult{
						ID:         fmt.Sprintf("%s-%s-%d", d.id, test.ID, time.Now().Unix()),
						DetectorID: d.id,
						Target:     target,
						Vulnerability: &Vulnerability{
							ID:          test.ID,
							Name:        test.Name,
							Description: test.Description,
							Category:    test.Category,
							Severity:    test.Severity,
							CVSS:        test.CVSS,
							CWE:         test.CWE,
							OWASP:       test.OWASP,
							References:  test.References,
							Remediation: test.Remediation,
						},
						Evidence: &Evidence{
							Type:     "payload_response",
							Data:     matcher.Value,
							Request:  payload.Value,
							Response: response,
							Location: target,
						},
						Timestamp:  time.Now(),
						Confidence: 70, // Higher base confidence for active detection
						Severity:   test.Severity,
						Status:     "detected",
						Metadata:   make(map[string]interface{}),
					}
					
					results = append(results, result)
					break // Move to next payload after first match
				}
			}
		}
	}
	
	return results, nil
}

// sendPayload sends a payload to a target
func (d *ActiveDetector) sendPayload(target string, payload *TestPayload, options *DetectionOptions) (string, error) {
	// This is a placeholder for sending payloads
	// A real implementation would send the payload to the target
	
	return "", nil
}

// matchesResponse checks if a response matches a matcher
func (d *ActiveDetector) matchesResponse(response string, matcher *TestMatcher) bool {
	// This is a placeholder for response matching
	// A real implementation would check if the response matches the matcher
	
	return false
}

// HybridDetector implements both passive and active detection
type HybridDetector struct {
	// ID is the detector ID
	id string
	
	// Name is the detector name
	name string
	
	// Description is the detector description
	description string
	
	// Capabilities are the detector capabilities
	capabilities *DetectorCapabilities
	
	// PassiveDetector is the passive detector
	passiveDetector *PassiveDetector
	
	// ActiveDetector is the active detector
	activeDetector *ActiveDetector
}

// NewHybridDetector creates a new hybrid detector
func NewHybridDetector(id, name, description string) *HybridDetector {
	return &HybridDetector{
		id:              id,
		name:            name,
		description:     description,
		capabilities: &DetectorCapabilities{
			SupportedProtocols:       []string{"http", "https"},
			SupportedVulnerabilities: []string{},
			RequiresAuthentication:   false,
			IsPassive:                true,
			IsActive:                 true,
		},
		passiveDetector: NewPassiveDetector(id+"-passive", name+" (Passive)", description),
		activeDetector:  NewActiveDetector(id+"-active", name+" (Active)", description),
	}
}

// ID returns the detector ID
func (d *HybridDetector) ID() string {
	return d.id
}

// Name returns the detector name
func (d *HybridDetector) Name() string {
	return d.name
}

// Description returns the detector description
func (d *HybridDetector) Description() string {
	return d.description
}

// Capabilities returns the detector capabilities
func (d *HybridDetector) Capabilities() *DetectorCapabilities {
	return d.capabilities
}

// AddSignature adds a vulnerability signature to the passive detector
func (d *HybridDetector) AddSignature(signature *VulnerabilitySignature) {
	d.passiveDetector.AddSignature(signature)
	
	// Update supported vulnerabilities
	d.updateSupportedVulnerabilities()
}

// AddTest adds a vulnerability test to the active detector
func (d *HybridDetector) AddTest(test *VulnerabilityTest) {
	d.activeDetector.AddTest(test)
	
	// Update supported vulnerabilities
	d.updateSupportedVulnerabilities()
}

// updateSupportedVulnerabilities updates the supported vulnerabilities
func (d *HybridDetector) updateSupportedVulnerabilities() {
	// Combine supported vulnerabilities from both detectors
	vulnTypes := make(map[string]bool)
	
	for _, vulnType := range d.passiveDetector.Capabilities().SupportedVulnerabilities {
		vulnTypes[vulnType] = true
	}
	
	for _, vulnType := range d.activeDetector.Capabilities().SupportedVulnerabilities {
		vulnTypes[vulnType] = true
	}
	
	// Convert map to slice
	d.capabilities.SupportedVulnerabilities = make([]string, 0, len(vulnTypes))
	for vulnType := range vulnTypes {
		d.capabilities.SupportedVulnerabilities = append(d.capabilities.SupportedVulnerabilities, vulnType)
	}
}

// Detect performs vulnerability detection
func (d *HybridDetector) Detect(target string, options *DetectionOptions) ([]*DetectionResult, error) {
	var results []*DetectionResult
	
	// Run passive detection if enabled
	if options.IncludePassive {
		passiveResults, err := d.passiveDetector.Detect(target, options)
		if err != nil {
			// Log error but continue with active detection
			fmt.Printf("Error running passive detection: %v\n", err)
		} else {
			results = append(results, passiveResults...)
		}
	}
	
	// Run active detection if enabled
	if options.IncludeActive {
		activeResults, err := d.activeDetector.Detect(target, options)
		if err != nil {
			// Log error but return passive results
			fmt.Printf("Error running active detection: %v\n", err)
		} else {
			results = append(results, activeResults...)
		}
	}
	
	return results, nil
}

// CorrelationAnalyzer analyzes and correlates detection results
type CorrelationAnalyzer struct {
	// Name is the analyzer name
	name string
	
	// Rules contains correlation rules
	rules []*CorrelationRule
}

// CorrelationRule represents a correlation rule
type CorrelationRule struct {
	// ID is the rule ID
	ID string
	
	// Name is the rule name
	Name string
	
	// Description is the rule description
	Description string
	
	// Conditions are the rule conditions
	Conditions []string
	
	// Action is the rule action
	Action string
	
	// Parameters contains rule parameters
	Parameters map[string]interface{}
}

// NewCorrelationAnalyzer creates a new correlation analyzer
func NewCorrelationAnalyzer() *CorrelationAnalyzer {
	return &CorrelationAnalyzer{
		name:  "CorrelationAnalyzer",
		rules: make([]*CorrelationRule, 0),
	}
}

// Name returns the analyzer name
func (a *CorrelationAnalyzer) Name() string {
	return a.name
}

// AddRule adds a correlation rule
func (a *CorrelationAnalyzer) AddRule(rule *CorrelationRule) {
	a.rules = append(a.rules, rule)
}

// Analyze analyzes detection results
func (a *CorrelationAnalyzer) Analyze(results []*DetectionResult) ([]*DetectionResult, error) {
	// Group results by target
	resultsByTarget := make(map[string][]*DetectionResult)
	for _, result := range results {
		resultsByTarget[result.Target] = append(resultsByTarget[result.Target], result)
	}
	
	var analyzedResults []*DetectionResult
	
	// Apply correlation rules to each target
	for target, targetResults := range resultsByTarget {
		// Apply rules
		for _, rule := range a.rules {
			if a.matchesRule(targetResults, rule) {
				// Apply rule action
				switch rule.Action {
				case "merge":
					// Merge results
					mergedResult, err := a.mergeResults(targetResults, rule.Parameters)
					if err != nil {
						// Log error but continue with other rules
						fmt.Printf("Error merging results: %v\n", err)
						continue
					}
					
					analyzedResults = append(analyzedResults, mergedResult)
				case "elevate":
					// Elevate severity
					elevatedResults, err := a.elevateSeverity(targetResults, rule.Parameters)
					if err != nil {
						// Log error but continue with other rules
						fmt.Printf("Error elevating severity: %v\n", err)
						continue
					}
					
					analyzedResults = append(analyzedResults, elevatedResults...)
				case "suppress":
					// Suppress results
					// Do nothing, results are not added to analyzedResults
				default:
					// Add results as-is
					analyzedResults = append(analyzedResults, targetResults...)
				}
			} else {
				// Add results as-is
				analyzedResults = append(analyzedResults, targetResults...)
			}
		}
	}
	
	return analyzedResults, nil
}

// matchesRule checks if results match a rule
func (a *CorrelationAnalyzer) matchesRule(results []*DetectionResult, rule *CorrelationRule) bool {
	// This is a placeholder for rule matching
	// A real implementation would check if the results match the rule
	
	return false
}

// mergeResults merges multiple results into one
func (a *CorrelationAnalyzer) mergeResults(results []*DetectionResult, parameters map[string]interface{}) (*DetectionResult, error) {
	// This is a placeholder for result merging
	// A real implementation would merge the results
	
	return nil, fmt.Errorf("result merging not implemented")
}

// elevateSeverity elevates the severity of results
func (a *CorrelationAnalyzer) elevateSeverity(results []*DetectionResult, parameters map[string]interface{}) ([]*DetectionResult, error) {
	// This is a placeholder for severity elevation
	// A real implementation would elevate the severity of the results
	
	return nil, fmt.Errorf("severity elevation not implemented")
}

// ContextualAnalyzer analyzes detection results in context
type ContextualAnalyzer struct {
	// Name is the analyzer name
	name string
	
	// ContextProviders contains context providers
	contextProviders []ContextProvider
}

// ContextProvider provides context for analysis
type ContextProvider interface {
	// GetContext gets context for a target
	GetContext(target string) (map[string]interface{}, error)
	
	// Name returns the provider name
	Name() string
}

// NewContextualAnalyzer creates a new contextual analyzer
func NewContextualAnalyzer() *ContextualAnalyzer {
	return &ContextualAnalyzer{
		name:             "ContextualAnalyzer",
		contextProviders: make([]ContextProvider, 0),
	}
}

// Name returns the analyzer name
func (a *ContextualAnalyzer) Name() string {
	return a.name
}

// AddContextProvider adds a context provider
func (a *ContextualAnalyzer) AddContextProvider(provider ContextProvider) {
	a.contextProviders = append(a.contextProviders, provider)
}

// Analyze analyzes detection results
func (a *ContextualAnalyzer) Analyze(results []*DetectionResult) ([]*DetectionResult, error) {
	var analyzedResults []*DetectionResult
	
	// Group results by target
	resultsByTarget := make(map[string][]*DetectionResult)
	for _, result := range results {
		resultsByTarget[result.Target] = append(resultsByTarget[result.Target], result)
	}
	
	// Analyze each target
	for target, targetResults := range resultsByTarget {
		// Get context for target
		context := make(map[string]interface{})
		
		for _, provider := range a.contextProviders {
			providerContext, err := provider.GetContext(target)
			if err != nil {
				// Log error but continue with other providers
				fmt.Printf("Error getting context from provider %s: %v\n", provider.Name(), err)
				continue
			}
			
			// Merge context
			for key, value := range providerContext {
				context[key] = value
			}
		}
		
		// Analyze results with context
		for _, result := range targetResults {
			analyzedResult := a.analyzeResult(result, context)
			analyzedResults = append(analyzedResults, analyzedResult)
		}
	}
	
	return analyzedResults, nil
}

// analyzeResult analyzes a result with context
func (a *ContextualAnalyzer) analyzeResult(result *DetectionResult, context map[string]interface{}) *DetectionResult {
	// This is a placeholder for result analysis
	// A real implementation would analyze the result with context
	
	return result
}

// TechnologyContextProvider provides technology context
type TechnologyContextProvider struct {
	// Name is the provider name
	name string
	
	// TechnologyDetector detects technologies
	technologyDetector *TechnologyDetector
}

// TechnologyDetector detects technologies
type TechnologyDetector struct {
	// Signatures contains technology signatures
	signatures []*TechnologySignature
}

// TechnologySignature represents a technology signature
type TechnologySignature struct {
	// Name is the technology name
	Name string
	
	// Version is the technology version
	Version string
	
	// Category is the technology category
	Category string
	
	// Patterns contains detection patterns
	Patterns []*DetectionPattern
}

// NewTechnologyContextProvider creates a new technology context provider
func NewTechnologyContextProvider() *TechnologyContextProvider {
	return &TechnologyContextProvider{
		name:               "TechnologyContextProvider",
		technologyDetector: NewTechnologyDetector(),
	}
}

// Name returns the provider name
func (p *TechnologyContextProvider) Name() string {
	return p.name
}

// GetContext gets context for a target
func (p *TechnologyContextProvider) GetContext(target string) (map[string]interface{}, error) {
	// Detect technologies
	technologies, err := p.technologyDetector.Detect(target)
	if err != nil {
		return nil, err
	}
	
	// Create context
	context := map[string]interface{}{
		"technologies": technologies,
	}
	
	return context, nil
}

// NewTechnologyDetector creates a new technology detector
func NewTechnologyDetector() *TechnologyDetector {
	return &TechnologyDetector{
		signatures: make([]*TechnologySignature, 0),
	}
}

// AddSignature adds a technology signature
func (d *TechnologyDetector) AddSignature(signature *TechnologySignature) {
	d.signatures = append(d.signatures, signature)
}

// Detect detects technologies
func (d *TechnologyDetector) Detect(target string) ([]*TechnologySignature, error) {
	// This is a placeholder for technology detection
	// A real implementation would detect technologies
	
	return nil, nil
}

// VulnerabilityContextProvider provides vulnerability context
type VulnerabilityContextProvider struct {
	// Name is the provider name
	name string
	
	// VulnerabilityDatabase is the vulnerability database
	vulnerabilityDatabase *VulnerabilityDatabase
}

// VulnerabilityDatabase is a database of vulnerabilities
type VulnerabilityDatabase struct {
	// Vulnerabilities contains vulnerabilities
	vulnerabilities map[string]*Vulnerability
}

// NewVulnerabilityContextProvider creates a new vulnerability context provider
func NewVulnerabilityContextProvider() *VulnerabilityContextProvider {
	return &VulnerabilityContextProvider{
		name:                 "VulnerabilityContextProvider",
		vulnerabilityDatabase: NewVulnerabilityDatabase(),
	}
}

// Name returns the provider name
func (p *VulnerabilityContextProvider) Name() string {
	return p.name
}

// GetContext gets context for a target
func (p *VulnerabilityContextProvider) GetContext(target string) (map[string]interface{}, error) {
	// This is a placeholder for getting vulnerability context
	// A real implementation would get vulnerability context
	
	return nil, nil
}

// NewVulnerabilityDatabase creates a new vulnerability database
func NewVulnerabilityDatabase() *VulnerabilityDatabase {
	return &VulnerabilityDatabase{
		vulnerabilities: make(map[string]*Vulnerability),
	}
}

// AddVulnerability adds a vulnerability
func (d *VulnerabilityDatabase) AddVulnerability(vulnerability *Vulnerability) {
	d.vulnerabilities[vulnerability.ID] = vulnerability
}

// GetVulnerability gets a vulnerability
func (d *VulnerabilityDatabase) GetVulnerability(id string) (*Vulnerability, bool) {
	vulnerability, exists := d.vulnerabilities[id]
	return vulnerability, exists
}

// DetectorFactory creates detectors
type DetectorFactory struct {
	// Registry is the detector registry
	registry map[string]Detector
}

// NewDetectorFactory creates a new detector factory
func NewDetectorFactory() *DetectorFactory {
	return &DetectorFactory{
		registry: make(map[string]Detector),
	}
}

// RegisterDetector registers a detector
func (f *DetectorFactory) RegisterDetector(detector Detector) {
	f.registry[detector.ID()] = detector
}

// CreateDetector creates a detector
func (f *DetectorFactory) CreateDetector(id string) (Detector, error) {
	detector, exists := f.registry[id]
	if !exists {
		return nil, fmt.Errorf("detector not found: %s", id)
	}
	
	return detector, nil
}

// CreatePassiveDetector creates a passive detector
func (f *DetectorFactory) CreatePassiveDetector(id, name, description string) *PassiveDetector {
	detector := NewPassiveDetector(id, name, description)
	f.RegisterDetector(detector)
	return detector
}

// CreateActiveDetector creates an active detector
func (f *DetectorFactory) CreateActiveDetector(id, name, description string) *ActiveDetector {
	detector := NewActiveDetector(id, name, description)
	f.RegisterDetector(detector)
	return detector
}

// CreateHybridDetector creates a hybrid detector
func (f *DetectorFactory) CreateHybridDetector(id, name, description string) *HybridDetector {
	detector := NewHybridDetector(id, name, description)
	f.RegisterDetector(detector)
	return detector
}

// AnalyzerFactory creates analyzers
type AnalyzerFactory struct {
	// Registry is the analyzer registry
	registry map[string]ResultAnalyzer
}

// NewAnalyzerFactory creates a new analyzer factory
func NewAnalyzerFactory() *AnalyzerFactory {
	return &AnalyzerFactory{
		registry: make(map[string]ResultAnalyzer),
	}
}

// RegisterAnalyzer registers an analyzer
func (f *AnalyzerFactory) RegisterAnalyzer(analyzer ResultAnalyzer) {
	f.registry[analyzer.Name()] = analyzer
}

// CreateAnalyzer creates an analyzer
func (f *AnalyzerFactory) CreateAnalyzer(name string) (ResultAnalyzer, error) {
	analyzer, exists := f.registry[name]
	if !exists {
		return nil, fmt.Errorf("analyzer not found: %s", name)
	}
	
	return analyzer, nil
}

// CreateCorrelationAnalyzer creates a correlation analyzer
func (f *AnalyzerFactory) CreateCorrelationAnalyzer() *CorrelationAnalyzer {
	analyzer := NewCorrelationAnalyzer()
	f.RegisterAnalyzer(analyzer)
	return analyzer
}

// CreateContextualAnalyzer creates a contextual analyzer
func (f *AnalyzerFactory) CreateContextualAnalyzer() *ContextualAnalyzer {
	analyzer := NewContextualAnalyzer()
	f.RegisterAnalyzer(analyzer)
	return analyzer
}
