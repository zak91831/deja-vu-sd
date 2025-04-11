package persona

import (
	"fmt"
	"strings"
	"time"
)

// PersonaManager manages the available personas and their selection
type PersonaManager struct {
	personas       map[string]*Persona
	currentPersona *Persona
	defaultPersona string
}

// NewPersonaManager creates a new persona manager
func NewPersonaManager() *PersonaManager {
	manager := &PersonaManager{
		personas:       make(map[string]*Persona),
		defaultPersona: "standard",
	}
	
	// Add default personas
	manager.addDefaultPersonas()
	
	// Set current persona to default
	manager.currentPersona = manager.personas[manager.defaultPersona]
	
	return manager
}

// AddPersona adds a persona to the manager
func (m *PersonaManager) AddPersona(persona *Persona) {
	m.personas[persona.Name] = persona
}

// GetPersona returns a persona by name
func (m *PersonaManager) GetPersona(name string) (*Persona, error) {
	persona, ok := m.personas[name]
	if !ok {
		return nil, fmt.Errorf("persona %s not found", name)
	}
	return persona, nil
}

// SetCurrentPersona sets the current persona
func (m *PersonaManager) SetCurrentPersona(name string) error {
	persona, err := m.GetPersona(name)
	if err != nil {
		return err
	}
	
	m.currentPersona = persona
	return nil
}

// GetCurrentPersona returns the current persona
func (m *PersonaManager) GetCurrentPersona() *Persona {
	return m.currentPersona
}

// ListPersonas returns a list of all persona names
func (m *PersonaManager) ListPersonas() []string {
	names := make([]string, 0, len(m.personas))
	for name := range m.personas {
		names = append(names, name)
	}
	return names
}

// addDefaultPersonas adds default personas to the manager
func (m *PersonaManager) addDefaultPersonas() {
	// Standard persona
	standard := &Persona{
		Name:      "standard",
		Delay:     DelayRange{Min: 0, Max: 100 * time.Millisecond},
		RateLimit: 150,
		UserAgent: "Deja Vu Scanner v1.0",
		Headers:   make(map[string]string),
		Tags:      []string{},
	}
	m.AddPersona(standard)

	// Stealthy persona
	stealthy := &Persona{
		Name:      "stealthy",
		Delay:     DelayRange{Min: 1 * time.Second, Max: 3 * time.Second},
		RateLimit: 10,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
		},
		Tags: []string{"stealthy", "evasion"},
	}
	m.AddPersona(stealthy)

	// Aggressive persona
	aggressive := &Persona{
		Name:      "aggressive",
		Delay:     DelayRange{Min: 0, Max: 10 * time.Millisecond},
		RateLimit: 500,
		UserAgent: "Deja Vu Scanner v1.0 (Fast Mode)",
		Headers:   make(map[string]string),
		Tags:      []string{"aggressive", "fast"},
	}
	m.AddPersona(aggressive)

	// APT persona
	apt := &Persona{
		Name:      "apt",
		Delay:     DelayRange{Min: 500 * time.Millisecond, Max: 2 * time.Second},
		RateLimit: 20,
		UserAgent: "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Connection":      "keep-alive",
		},
		Tags: []string{"apt", "targeted", "stealthy"},
	}
	m.AddPersona(apt)
}

// CreatePersonaFromConfig creates a persona from configuration
func CreatePersonaFromConfig(name string, config map[string]interface{}) (*Persona, error) {
	persona := &Persona{
		Name:    name,
		Headers: make(map[string]string),
		Tags:    make([]string, 0),
	}
	
	// Parse delay
	if delayStr, ok := config["delay"].(string); ok {
		delayRange, err := parseDelayRange(delayStr)
		if err != nil {
			return nil, fmt.Errorf("invalid delay range: %w", err)
		}
		persona.Delay = delayRange
	}
	
	// Parse rate limit
	if rateLimit, ok := config["rate_limit"].(int); ok {
		persona.RateLimit = rateLimit
	}
	
	// Parse user agent
	if userAgent, ok := config["user_agent"].(string); ok {
		persona.UserAgent = userAgent
	}
	
	// Parse headers
	if headers, ok := config["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if strValue, ok := value.(string); ok {
				persona.Headers[key] = strValue
			}
		}
	}
	
	// Parse tags
	if tags, ok := config["tags"].([]interface{}); ok {
		for _, tag := range tags {
			if strTag, ok := tag.(string); ok {
				persona.Tags = append(persona.Tags, strTag)
			}
		}
	}
	
	return persona, nil
}
