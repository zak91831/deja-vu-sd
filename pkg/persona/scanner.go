package persona

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// PersonaScanner implements personality-driven vulnerability scanning
type PersonaScanner struct {
	// ID is the scanner ID
	ID string
	
	// Name is the scanner name
	Name string
	
	// Description is the scanner description
	Description string
	
	// Personas contains available scanning personas
	Personas map[string]*ScanningPersona
	
	// ActivePersona is the currently active persona
	ActivePersona *ScanningPersona
	
	// Options contains scanner options
	Options *PersonaOptions
}

// ScanningPersona represents a scanning personality profile
type ScanningPersona struct {
	// ID is the persona ID
	ID string
	
	// Name is the persona name
	Name string
	
	// Description is the persona description
	Description string
	
	// Category is the persona category
	Category string
	
	// Behaviors contains persona behaviors
	Behaviors []*PersonaBehavior
	
	// Headers contains HTTP headers to use
	Headers map[string]string
	
	// UserAgents contains user agents to rotate
	UserAgents []string
	
	// RateLimiting contains rate limiting settings
	RateLimiting *RateLimitingSettings
	
	// ProxySettings contains proxy settings
	ProxySettings *ProxySettings
	
	// Evasion contains evasion techniques
	Evasion *EvasionTechniques
	
	// Metadata contains additional metadata
	Metadata map[string]interface{}
}

// PersonaBehavior represents a scanning behavior
type PersonaBehavior struct {
	// Type is the behavior type
	Type string
	
	// Value is the behavior value
	Value string
	
	// Weight is the behavior weight
	Weight int
	
	// Condition is the behavior condition
	Condition string
}

// RateLimitingSettings contains rate limiting settings
type RateLimitingSettings struct {
	// RequestsPerSecond is the maximum requests per second
	RequestsPerSecond float64
	
	// BurstSize is the burst size
	BurstSize int
	
	// Strategy is the rate limiting strategy
	Strategy string
	
	// Jitter is the jitter percentage
	Jitter float64
}

// ProxySettings contains proxy settings
type ProxySettings struct {
	// UseProxy indicates whether to use a proxy
	UseProxy bool
	
	// ProxyURL is the proxy URL
	ProxyURL string
	
	// RotateProxies indicates whether to rotate proxies
	RotateProxies bool
	
	// ProxyList contains proxy URLs to rotate
	ProxyList []string
	
	// RotationInterval is the proxy rotation interval
	RotationInterval time.Duration
}

// EvasionTechniques contains evasion techniques
type EvasionTechniques struct {
	// UserAgentRotation indicates whether to rotate user agents
	UserAgentRotation bool
	
	// HeaderManipulation indicates whether to manipulate headers
	HeaderManipulation bool
	
	// RequestDelays indicates whether to add random delays
	RequestDelays bool
	
	// PathObfuscation indicates whether to obfuscate paths
	PathObfuscation bool
	
	// ParameterPollution indicates whether to use parameter pollution
	ParameterPollution bool
}

// PersonaOptions contains persona scanner options
type PersonaOptions struct {
	// DefaultPersona is the default persona ID
	DefaultPersona string
	
	// EnableBehaviorLearning indicates whether to enable behavior learning
	EnableBehaviorLearning bool
	
	// EnableAdaptiveRateLimiting indicates whether to enable adaptive rate limiting
	EnableAdaptiveRateLimiting bool
	
	// EnableEvasionTechniques indicates whether to enable evasion techniques
	EnableEvasionTechniques bool
	
	// MaxConcurrentScans is the maximum concurrent scans
	MaxConcurrentScans int
}

// NewPersonaScanner creates a new persona scanner
func NewPersonaScanner() *PersonaScanner {
	return &PersonaScanner{
		ID:          "persona-scanner",
		Name:        "Personality-Driven Scanner",
		Description: "Scanner with configurable scanning personalities",
		Personas:    make(map[string]*ScanningPersona),
		Options:     NewPersonaOptions(),
	}
}

// AddPersona adds a scanning persona
func (s *PersonaScanner) AddPersona(persona *ScanningPersona) {
	s.Personas[persona.ID] = persona
}

// SetActivePersona sets the active persona
func (s *PersonaScanner) SetActivePersona(personaID string) error {
	persona, exists := s.Personas[personaID]
	if !exists {
		return fmt.Errorf("persona not found: %s", personaID)
	}
	
	s.ActivePersona = persona
	return nil
}

// SetOptions sets scanner options
func (s *PersonaScanner) SetOptions(options *PersonaOptions) {
	s.Options = options
	
	// Set default persona if specified
	if options.DefaultPersona != "" {
		if persona, exists := s.Personas[options.DefaultPersona]; exists {
			s.ActivePersona = persona
		}
	}
}

// Scan performs personality-driven vulnerability scanning
func (s *PersonaScanner) Scan(target string) (*PersonaScanResult, error) {
	// Ensure active persona is set
	if s.ActivePersona == nil {
		// Use default persona if available
		if s.Options.DefaultPersona != "" {
			if err := s.SetActivePersona(s.Options.DefaultPersona); err != nil {
				return nil, fmt.Errorf("failed to set default persona: %w", err)
			}
		} else {
			return nil, fmt.Errorf("no active persona set")
		}
	}
	
	// Create HTTP client with persona settings
	client, err := s.createHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	
	// Create scan result
	result := &PersonaScanResult{
		Target:    target,
		Persona:   s.ActivePersona,
		Timestamp: time.Now(),
		Status:    "started",
		Metadata:  make(map[string]interface{}),
	}
	
	// Perform scan
	// This is a placeholder for the actual scanning logic
	// A real implementation would perform the scan using the configured persona
	
	// Update scan result
	result.Status = "completed"
	result.EndTimestamp = time.Now()
	result.Duration = result.EndTimestamp.Sub(result.Timestamp)
	
	return result, nil
}

// createHTTPClient creates an HTTP client with persona settings
func (s *PersonaScanner) createHTTPClient() (*http.Client, error) {
	// This is a placeholder for creating an HTTP client with persona settings
	// A real implementation would configure the client based on the active persona
	
	return &http.Client{}, nil
}

// PersonaScanResult represents a persona scan result
type PersonaScanResult struct {
	// Target is the scan target
	Target string
	
	// Persona is the scanning persona
	Persona *ScanningPersona
	
	// Timestamp is the scan start timestamp
	Timestamp time.Time
	
	// EndTimestamp is the scan end timestamp
	EndTimestamp time.Time
	
	// Duration is the scan duration
	Duration time.Duration
	
	// Status is the scan status
	Status string
	
	// Metadata contains additional metadata
	Metadata map[string]interface{}
}

// NewPersonaOptions creates new persona options
func NewPersonaOptions() *PersonaOptions {
	return &PersonaOptions{
		DefaultPersona:           "",
		EnableBehaviorLearning:   true,
		EnableAdaptiveRateLimiting: true,
		EnableEvasionTechniques:  true,
		MaxConcurrentScans:       5,
	}
}

// StandardPersona creates a standard scanning persona
func StandardPersona() *ScanningPersona {
	return &ScanningPersona{
		ID:          "standard",
		Name:        "Standard Scanner",
		Description: "Standard scanning profile with balanced settings",
		Category:    "standard",
		Behaviors: []*PersonaBehavior{
			{Type: "scan_depth", Value: "medium", Weight: 5},
			{Type: "scan_speed", Value: "normal", Weight: 5},
			{Type: "payload_type", Value: "standard", Weight: 5},
		},
		Headers: map[string]string{
			"User-Agent": "Deja-Vu-Scanner/2.0",
		},
		UserAgents: []string{
			"Deja-Vu-Scanner/2.0",
			"Mozilla/5.0 (compatible; Deja-Vu-Scanner/2.0)",
		},
		RateLimiting: &RateLimitingSettings{
			RequestsPerSecond: 10,
			BurstSize:         20,
			Strategy:          "token_bucket",
			Jitter:            0.1,
		},
		ProxySettings: &ProxySettings{
			UseProxy:      false,
			RotateProxies: false,
		},
		Evasion: &EvasionTechniques{
			UserAgentRotation:  false,
			HeaderManipulation: false,
			RequestDelays:      false,
			PathObfuscation:    false,
			ParameterPollution: false,
		},
		Metadata: make(map[string]interface{}),
	}
}

// StealthyPersona creates a stealthy scanning persona
func StealthyPersona() *ScanningPersona {
	return &ScanningPersona{
		ID:          "stealthy",
		Name:        "Stealthy Scanner",
		Description: "Low-profile scanning to avoid detection",
		Category:    "evasive",
		Behaviors: []*PersonaBehavior{
			{Type: "scan_depth", Value: "shallow", Weight: 3},
			{Type: "scan_speed", Value: "slow", Weight: 8},
			{Type: "payload_type", Value: "minimal", Weight: 7},
		},
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		},
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		},
		RateLimiting: &RateLimitingSettings{
			RequestsPerSecond: 1,
			BurstSize:         2,
			Strategy:          "adaptive",
			Jitter:            0.5,
		},
		ProxySettings: &ProxySettings{
			UseProxy:          true,
			RotateProxies:     true,
			RotationInterval:  5 * time.Minute,
		},
		Evasion: &EvasionTechniques{
			UserAgentRotation:  true,
			HeaderManipulation: true,
			RequestDelays:      true,
			PathObfuscation:    true,
			ParameterPollution: false,
		},
		Metadata: make(map[string]interface{}),
	}
}

// AggressivePersona creates an aggressive scanning persona
func AggressivePersona() *ScanningPersona {
	return &ScanningPersona{
		ID:          "aggressive",
		Name:        "Aggressive Scanner",
		Description: "High-speed, thorough scanning",
		Category:    "aggressive",
		Behaviors: []*PersonaBehavior{
			{Type: "scan_depth", Value: "deep", Weight: 9},
			{Type: "scan_speed", Value: "fast", Weight: 9},
			{Type: "payload_type", Value: "extensive", Weight: 8},
		},
		Headers: map[string]string{
			"User-Agent": "Deja-Vu-Scanner/2.0 (Aggressive Mode)",
		},
		UserAgents: []string{
			"Deja-Vu-Scanner/2.0 (Aggressive Mode)",
		},
		RateLimiting: &RateLimitingSettings{
			RequestsPerSecond: 50,
			BurstSize:         100,
			Strategy:          "fixed",
			Jitter:            0,
		},
		ProxySettings: &ProxySettings{
			UseProxy:      false,
			RotateProxies: false,
		},
		Evasion: &EvasionTechniques{
			UserAgentRotation:  false,
			HeaderManipulation: false,
			RequestDelays:      false,
			PathObfuscation:    false,
			ParameterPollution: true,
		},
		Metadata: make(map[string]interface{}),
	}
}

// APTPersona creates an APT-like scanning persona
func APTPersona() *ScanningPersona {
	return &ScanningPersona{
		ID:          "apt",
		Name:        "APT Scanner",
		Description: "Advanced Persistent Threat simulation",
		Category:    "targeted",
		Behaviors: []*PersonaBehavior{
			{Type: "scan_depth", Value: "targeted", Weight: 7},
			{Type: "scan_speed", Value: "variable", Weight: 6},
			{Type: "payload_type", Value: "sophisticated", Weight: 9},
		},
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		},
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.55",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		},
		RateLimiting: &RateLimitingSettings{
			RequestsPerSecond: 2,
			BurstSize:         5,
			Strategy:          "variable",
			Jitter:            0.7,
		},
		ProxySettings: &ProxySettings{
			UseProxy:          true,
			RotateProxies:     true,
			RotationInterval:  30 * time.Minute,
		},
		Evasion: &EvasionTechniques{
			UserAgentRotation:  true,
			HeaderManipulation: true,
			RequestDelays:      true,
			PathObfuscation:    true,
			ParameterPollution: true,
		},
		Metadata: make(map[string]interface{}),
	}
}

// PersonaFactory creates scanning personas
type PersonaFactory struct {
	// Personas contains registered personas
	Personas map[string]*ScanningPersona
}

// NewPersonaFactory creates a new persona factory
func NewPersonaFactory() *PersonaFactory {
	return &PersonaFactory{
		Personas: make(map[string]*ScanningPersona),
	}
}

// RegisterPersona registers a scanning persona
func (f *PersonaFactory) RegisterPersona(persona *ScanningPersona) {
	f.Personas[persona.ID] = persona
}

// CreatePersona creates a scanning persona
func (f *PersonaFactory) CreatePersona(id string) (*ScanningPersona, error) {
	persona, exists := f.Personas[id]
	if !exists {
		return nil, fmt.Errorf("persona not found: %s", id)
	}
	
	return persona, nil
}

// CreateStandardPersonas creates standard scanning personas
func (f *PersonaFactory) CreateStandardPersonas() {
	f.RegisterPersona(StandardPersona())
	f.RegisterPersona(StealthyPersona())
	f.RegisterPersona(AggressivePersona())
	f.RegisterPersona(APTPersona())
}

// PersonaManager manages scanning personas
type PersonaManager struct {
	// Scanner is the persona scanner
	Scanner *PersonaScanner
	
	// Factory is the persona factory
	Factory *PersonaFactory
	
	// Results contains scan results
	Results []*PersonaScanResult
	
	// Statistics contains scan statistics
	Statistics *PersonaStatistics
}

// PersonaStatistics contains persona scan statistics
type PersonaStatistics struct {
	// StartTime is the scan start time
	StartTime time.Time
	
	// EndTime is the scan end time
	EndTime time.Time
	
	// Duration is the scan duration
	Duration time.Duration
	
	// TargetCount is the number of targets
	TargetCount int
	
	// ResultCount is the number of results
	ResultCount int
	
	// ResultsByPersona contains result counts by persona
	ResultsByPersona map[string]int
}

// NewPersonaManager creates a new persona manager
func NewPersonaManager() *PersonaManager {
	factory := NewPersonaFactory()
	factory.CreateStandardPersonas()
	
	scanner := NewPersonaScanner()
	
	// Register standard personas
	for _, persona := range factory.Personas {
		scanner.AddPersona(persona)
	}
	
	return &PersonaManager{
		Scanner:    scanner,
		Factory:    factory,
		Results:    make([]*PersonaScanResult, 0),
		Statistics: NewPersonaStatistics(),
	}
}

// Scan performs personality-driven vulnerability scanning
func (m *PersonaManager) Scan(targets []string, personaID string) error {
	// Reset results and statistics
	m.Results = make([]*PersonaScanResult, 0)
	m.Statistics = NewPersonaStatistics()
	m.Statistics.StartTime = time.Now()
	m.Statistics.TargetCount = len(targets)
	
	// Set active persona
	if err := m.Scanner.SetActivePersona(personaID); err != nil {
		return fmt.Errorf("failed to set active persona: %w", err)
	}
	
	// Scan each target
	for _, target := range targets {
		result, err := m.Scanner.Scan(target)
		if err != nil {
			return fmt.Errorf("failed to scan target %s: %w", target, err)
		}
		
		m.Results = append(m.Results, result)
	}
	
	// Update statistics
	m.Statistics.EndTime = time.Now()
	m.Statistics.Duration = m.Statistics.EndTime.Sub(m.Statistics.StartTime)
	m.Statistics.ResultCount = len(m.Results)
	
	// Count results by persona
	for _, result := range m.Results {
		m.Statistics.ResultsByPersona[result.Persona.ID]++
	}
	
	return nil
}

// GetResults gets scan results
func (m *PersonaManager) GetResults() []*PersonaScanResult {
	return m.Results
}

// GetStatistics gets scan statistics
func (m *PersonaManager) GetStatistics() *PersonaStatistics {
	return m.Statistics
}

// NewPersonaStatistics creates new persona statistics
func NewPersonaStatistics() *PersonaStatistics {
	return &PersonaStatistics{
		ResultsByPersona: make(map[string]int),
	}
}

// PersonaBehaviorLearner learns scanning behaviors
type PersonaBehaviorLearner struct {
	// Behaviors contains learned behaviors
	Behaviors map[string][]*PersonaBehavior
	
	// LearningRate is the behavior learning rate
	LearningRate float64
	
	// MinSamples is the minimum number of samples for learning
	MinSamples int
}

// NewPersonaBehaviorLearner creates a new persona behavior learner
func NewPersonaBehaviorLearner() *PersonaBehaviorLearner {
	return &PersonaBehaviorLearner{
		Behaviors:    make(map[string][]*PersonaBehavior),
		LearningRate: 0.1,
		MinSamples:   10,
	}
}

// LearnFromResults learns behaviors from scan results
func (l *PersonaBehaviorLearner) LearnFromResults(results []*PersonaScanResult) {
	// This is a placeholder for behavior learning
	// A real implementation would analyze results and update behaviors
}

// GetLearnedBehaviors gets learned behaviors for a persona
func (l *PersonaBehaviorLearner) GetLearnedBehaviors(personaID string) []*PersonaBehavior {
	return l.Behaviors[personaID]
}

// PersonaAPI provides an API for personality-driven scanning
type PersonaAPI struct {
	// Manager is the persona manager
	Manager *PersonaManager
	
	// Learner is the behavior learner
	Learner *PersonaBehaviorLearner
}

// NewPersonaAPI creates a new persona API
func NewPersonaAPI() *PersonaAPI {
	return &PersonaAPI{
		Manager: NewPersonaManager(),
		Learner: NewPersonaBehaviorLearner(),
	}
}

// ScanWithPersona performs scanning with a specific persona
func (a *PersonaAPI) ScanWithPersona(targets []string, personaID string) ([]*PersonaScanResult, error) {
	// Perform scan
	err := a.Manager.Scan(targets, personaID)
	if err != nil {
		return nil, err
	}
	
	// Get results
	results := a.Manager.GetResults()
	
	// Learn from results if behavior learning is enabled
	if a.Manager.Scanner.Options.EnableBehaviorLearning {
		a.Learner.LearnFromResults(results)
	}
	
	return results, nil
}

// GetAvailablePersonas gets available scanning personas
func (a *PersonaAPI) GetAvailablePersonas() []*ScanningPersona {
	var personas []*ScanningPersona
	
	for _, persona := range a.Manager.Scanner.Personas {
		personas = append(personas, persona)
	}
	
	return personas
}

// CreateCustomPersona creates a custom scanning persona
func (a *PersonaAPI) CreateCustomPersona(id, name, description, category string) (*ScanningPersona, error) {
	// Check if persona already exists
	if _, exists := a.Manager.Scanner.Personas[id]; exists {
		return nil, fmt.Errorf("persona already exists: %s", id)
	}
	
	// Create persona
	persona := &ScanningPersona{
		ID:          id,
		Name:        name,
		Description: description,
		Category:    category,
		Behaviors:   make([]*PersonaBehavior, 0),
		Headers:     make(map[string]string),
		UserAgents:  make([]string, 0),
		RateLimiting: &RateLimitingSettings{
			RequestsPerSecond: 5,
			BurstSize:         10,
			Strategy:          "token_bucket",
			Jitter:            0.2,
		},
		ProxySettings: &ProxySettings{
			UseProxy:      false,
			RotateProxies: false,
		},
		Evasion: &EvasionTechniques{
			UserAgentRotation:  false,
			HeaderManipulation: false,
			RequestDelays:      false,
			PathObfuscation:    false,
			ParameterPollution: false,
		},
		Metadata: make(map[string]interface{}),
	}
	
	// Register persona
	a.Manager.Scanner.AddPersona(persona)
	a.Manager.Factory.RegisterPersona(persona)
	
	return persona, nil
}
