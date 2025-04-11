package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure for Deja Vu
type Config struct {
	Core     CoreConfig     `yaml:"core"`
	Features FeaturesConfig `yaml:"features"`
	Logging  LoggingConfig  `yaml:"logging"`
	HTTP     HTTPConfig     `yaml:"http"`
}

// CoreConfig contains settings for the core scanning engine
type CoreConfig struct {
	MaxTargets    int    `yaml:"max_targets"`
	MaxTemplates  int    `yaml:"max_templates"`
	RateLimit     int    `yaml:"rate_limit"`
	OutputFormat  string `yaml:"output_format"`
	TemplateDir   string `yaml:"template_dir"`
}

// FeaturesConfig contains settings for feature modules
type FeaturesConfig struct {
	TimeTravel TimeTravelConfig `yaml:"timetravel"`
	Persona    PersonaConfig    `yaml:"persona"`
	Adaptive   AdaptiveConfig   `yaml:"adaptive"`
}

// TimeTravelConfig contains settings for the time travel module
type TimeTravelConfig struct {
	Enabled        bool                `yaml:"enabled"`
	WaybackMachine WaybackMachineConfig `yaml:"wayback_machine"`
	CertHistory    CertHistoryConfig    `yaml:"cert_history"`
}

// WaybackMachineConfig contains settings for Wayback Machine integration
type WaybackMachineConfig struct {
	Enabled      bool `yaml:"enabled"`
	MaxSnapshots int  `yaml:"max_snapshots"`
	MaxAgeDays   int  `yaml:"max_age_days"`
}

// CertHistoryConfig contains settings for certificate history integration
type CertHistoryConfig struct {
	Enabled  bool `yaml:"enabled"`
	MaxCerts int  `yaml:"max_certs"`
}

// PersonaConfig contains settings for the persona module
type PersonaConfig struct {
	Enabled        bool      `yaml:"enabled"`
	DefaultPersona string    `yaml:"default_persona"`
	Personas       []Persona `yaml:"personas"`
}

// Persona represents a scanning persona configuration
type Persona struct {
	Name      string `yaml:"name"`
	Delay     string `yaml:"delay"`
	RateLimit int    `yaml:"rate_limit"`
	UserAgent string `yaml:"user_agent"`
}

// AdaptiveConfig contains settings for the adaptive learning module
type AdaptiveConfig struct {
	Enabled               bool                      `yaml:"enabled"`
	TechDetection         TechDetectionConfig       `yaml:"tech_detection"`
	TemplatePrioritization TemplatePrioritizationConfig `yaml:"template_prioritization"`
	FeedbackCollection    FeedbackCollectionConfig  `yaml:"feedback_collection"`
}

// TechDetectionConfig contains settings for technology detection
type TechDetectionConfig struct {
	Enabled bool `yaml:"enabled"`
}

// TemplatePrioritizationConfig contains settings for template prioritization
type TemplatePrioritizationConfig struct {
	Enabled bool `yaml:"enabled"`
}

// FeedbackCollectionConfig contains settings for feedback collection
type FeedbackCollectionConfig struct {
	Enabled bool `yaml:"enabled"`
}

// LoggingConfig contains settings for logging
type LoggingConfig struct {
	Level  string `yaml:"level"`
	File   string `yaml:"file"`
	Format string `yaml:"format"`
}

// HTTPConfig contains settings for HTTP requests
type HTTPConfig struct {
	Timeout           int  `yaml:"timeout"`
	FollowRedirects   bool `yaml:"follow_redirects"`
	MaxRedirects      int  `yaml:"max_redirects"`
	DisableCookieReuse bool `yaml:"disable_cookie_reuse"`
}

// LoadConfig loads configuration from a file
func LoadConfig(configPath string) (*Config, error) {
	// Default configuration
	config := &Config{
		Core: CoreConfig{
			MaxTargets:    25,
			MaxTemplates:  25,
			RateLimit:     150,
			OutputFormat:  "cli",
			TemplateDir:   "./templates",
		},
		Features: FeaturesConfig{
			TimeTravel: TimeTravelConfig{
				Enabled: false,
				WaybackMachine: WaybackMachineConfig{
					Enabled:      true,
					MaxSnapshots: 10,
					MaxAgeDays:   365,
				},
				CertHistory: CertHistoryConfig{
					Enabled:  true,
					MaxCerts: 5,
				},
			},
			Persona: PersonaConfig{
				Enabled:        false,
				DefaultPersona: "standard",
				Personas: []Persona{
					{
						Name:      "standard",
						Delay:     "0ms-100ms",
						RateLimit: 150,
						UserAgent: "Deja Vu Scanner v1.0",
					},
				},
			},
			Adaptive: AdaptiveConfig{
				Enabled: false,
				TechDetection: TechDetectionConfig{
					Enabled: true,
				},
				TemplatePrioritization: TemplatePrioritizationConfig{
					Enabled: true,
				},
				FeedbackCollection: FeedbackCollectionConfig{
					Enabled: true,
				},
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			File:   "",
			Format: "text",
		},
		HTTP: HTTPConfig{
			Timeout:           10,
			FollowRedirects:   true,
			MaxRedirects:      10,
			DisableCookieReuse: false,
		},
	}

	// Read configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		// If file doesn't exist, use default config
		if os.IsNotExist(err) {
			fmt.Printf("Config file %s not found, using default configuration\n", configPath)
			return config, nil
		}
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse YAML
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return config, nil
}
