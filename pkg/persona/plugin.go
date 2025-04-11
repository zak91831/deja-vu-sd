package persona

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/dejavu/scanner/pkg/plugins"
)

// Plugin implements the personality-driven scanning functionality
type Plugin struct {
	config         map[string]interface{}
	enabled        bool
	defaultPersona string
	personas       map[string]*Persona
	currentPersona *Persona
	random         *rand.Rand
}

// Persona represents a scanning persona with specific behaviors
type Persona struct {
	Name      string
	Delay     DelayRange
	RateLimit int
	UserAgent string
	Headers   map[string]string
	Tags      []string
}

// DelayRange represents a range of delay times
type DelayRange struct {
	Min time.Duration
	Max time.Duration
}

// NewPlugin creates a new persona plugin
func NewPlugin() plugins.Plugin {
	return &Plugin{
		personas: make(map[string]*Persona),
		random:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Name returns the name of the plugin
func (p *Plugin) Name() string {
	return "persona"
}

// Version returns the version of the plugin
func (p *Plugin) Version() string {
	return "1.0.0"
}

// Initialize initializes the plugin with the provided configuration
func (p *Plugin) Initialize(config map[string]interface{}) error {
	p.config = config

	// Extract persona configuration
	if defaultPersona, ok := config["default_persona"].(string); ok {
		p.defaultPersona = defaultPersona
	} else {
		p.defaultPersona = "standard"
	}

	// Extract personas
	if personasConfig, ok := config["personas"].([]interface{}); ok {
		for _, personaConfig := range personasConfig {
			if personaMap, ok := personaConfig.(map[string]interface{}); ok {
				persona, err := p.parsePersona(personaMap)
				if err != nil {
					return fmt.Errorf("failed to parse persona: %w", err)
				}
				p.personas[persona.Name] = persona
			}
		}
	}

	// If no personas were configured, add default ones
	if len(p.personas) == 0 {
		p.addDefaultPersonas()
	}

	// Set current persona to default
	if persona, ok := p.personas[p.defaultPersona]; ok {
		p.currentPersona = persona
	} else if len(p.personas) > 0 {
		// If default persona doesn't exist, use the first one
		for _, persona := range p.personas {
			p.currentPersona = persona
			break
		}
	} else {
		// If no personas exist, create a standard one
		p.addDefaultPersonas()
		p.currentPersona = p.personas["standard"]
	}

	return nil
}

// Start starts the plugin
func (p *Plugin) Start() error {
	fmt.Printf("[Persona] Plugin started with persona: %s\n", p.currentPersona.Name)
	return nil
}

// Stop stops the plugin
func (p *Plugin) Stop() error {
	fmt.Println("[Persona] Plugin stopped")
	return nil
}

// Hooks returns a map of hook functions that the plugin provides
func (p *Plugin) Hooks() map[string]interface{} {
	return map[string]interface{}{
		"pre_request":           p.modifyRequest,
		"pre_template_execution": p.prioritizeTemplates,
	}
}

// SetPersona sets the current persona
func (p *Plugin) SetPersona(name string) error {
	persona, ok := p.personas[name]
	if !ok {
		return fmt.Errorf("persona %s not found", name)
	}

	p.currentPersona = persona
	fmt.Printf("[Persona] Switched to persona: %s\n", name)
	return nil
}

// GetCurrentPersona returns the current persona
func (p *Plugin) GetCurrentPersona() *Persona {
	return p.currentPersona
}

// GetPersonas returns all available personas
func (p *Plugin) GetPersonas() map[string]*Persona {
	return p.personas
}

// modifyRequest modifies a request based on the current persona
func (p *Plugin) modifyRequest(request map[string]interface{}) {
	if p.currentPersona == nil {
		return
	}

	// Add persona-specific headers
	if headers, ok := request["headers"].(map[string]string); ok {
		// Set User-Agent if not already set
		if _, exists := headers["User-Agent"]; !exists && p.currentPersona.UserAgent != "" {
			headers["User-Agent"] = p.currentPersona.UserAgent
		}

		// Add other persona-specific headers
		for key, value := range p.currentPersona.Headers {
			if _, exists := headers[key]; !exists {
				headers[key] = value
			}
		}

		request["headers"] = headers
	}

	// Apply delay based on persona's delay range
	if p.currentPersona.Delay.Max > 0 {
		delay := p.randomDelay(p.currentPersona.Delay)
		time.Sleep(delay)
	}
}

// prioritizeTemplates prioritizes templates based on the current persona
func (p *Plugin) prioritizeTemplates(templates []interface{}, tags []string) []interface{} {
	if p.currentPersona == nil || len(p.currentPersona.Tags) == 0 {
		return templates
	}

	// This is a simplified implementation
	// In a real implementation, we would reorder templates based on persona tags
	fmt.Printf("[Persona] Prioritizing templates for persona: %s\n", p.currentPersona.Name)
	
	// For now, just return the original templates
	return templates
}

// parsePersona parses a persona from a configuration map
func (p *Plugin) parsePersona(config map[string]interface{}) (*Persona, error) {
	persona := &Persona{
		Headers: make(map[string]string),
		Tags:    make([]string, 0),
	}

	// Parse name
	if name, ok := config["name"].(string); ok {
		persona.Name = name
	} else {
		return nil, fmt.Errorf("persona name is required")
	}

	// Parse delay
	if delay, ok := config["delay"].(string); ok {
		delayRange, err := parseDelayRange(delay)
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

// addDefaultPersonas adds default personas
func (p *Plugin) addDefaultPersonas() {
	// Standard persona
	p.personas["standard"] = &Persona{
		Name:      "standard",
		Delay:     DelayRange{Min: 0, Max: 100 * time.Millisecond},
		RateLimit: 150,
		UserAgent: "Deja Vu Scanner v1.0",
		Headers:   make(map[string]string),
		Tags:      []string{},
	}

	// Stealthy persona
	p.personas["stealthy"] = &Persona{
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

	// Aggressive persona
	p.personas["aggressive"] = &Persona{
		Name:      "aggressive",
		Delay:     DelayRange{Min: 0, Max: 10 * time.Millisecond},
		RateLimit: 500,
		UserAgent: "Deja Vu Scanner v1.0 (Fast Mode)",
		Headers:   make(map[string]string),
		Tags:      []string{"aggressive", "fast"},
	}

	// APT persona
	p.personas["apt"] = &Persona{
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
}

// randomDelay returns a random delay within the specified range
func (p *Plugin) randomDelay(delay DelayRange) time.Duration {
	if delay.Min >= delay.Max {
		return delay.Min
	}

	delta := delay.Max - delay.Min
	return delay.Min + time.Duration(p.random.Int63n(int64(delta)))
}

// parseDelayRange parses a delay range string (e.g., "100ms-500ms")
func parseDelayRange(s string) (DelayRange, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return DelayRange{}, fmt.Errorf("invalid delay range format: %s", s)
	}

	min, err := time.ParseDuration(parts[0])
	if err != nil {
		return DelayRange{}, fmt.Errorf("invalid minimum delay: %w", err)
	}

	max, err := time.ParseDuration(parts[1])
	if err != nil {
		return DelayRange{}, fmt.Errorf("invalid maximum delay: %w", err)
	}

	if min > max {
		return DelayRange{}, fmt.Errorf("minimum delay cannot be greater than maximum delay")
	}

	return DelayRange{Min: min, Max: max}, nil
}
