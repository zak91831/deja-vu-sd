package adaptive

import (
	"fmt"
	"strings"
	"sync"

	"github.com/dejavu/scanner/pkg/core/target"
	"github.com/dejavu/scanner/pkg/core/template"
	"github.com/dejavu/scanner/pkg/plugins"
)

// Plugin implements the adaptive learning functionality
type Plugin struct {
	config            map[string]interface{}
	enabled           bool
	techDetection     bool
	templatePriority  bool
	feedbackCollection bool
	techStack         map[string]*TechStack
	templateStats     map[string]*TemplateStats
	mutex             sync.RWMutex
}

// TechStack represents a target's technology stack
type TechStack struct {
	Target      string
	Technologies map[string]float64 // Technology name -> confidence score
}

// TemplateStats represents statistics for a template
type TemplateStats struct {
	TemplateID  string
	Executions  int
	Matches     int
	SuccessRate float64
	Tags        []string
}

// NewPlugin creates a new adaptive learning plugin
func NewPlugin() plugins.Plugin {
	return &Plugin{
		techStack:     make(map[string]*TechStack),
		templateStats: make(map[string]*TemplateStats),
	}
}

// Name returns the name of the plugin
func (p *Plugin) Name() string {
	return "adaptive"
}

// Version returns the version of the plugin
func (p *Plugin) Version() string {
	return "1.0.0"
}

// Initialize initializes the plugin with the provided configuration
func (p *Plugin) Initialize(config map[string]interface{}) error {
	p.config = config

	// Extract configuration
	if techDetection, ok := config["tech_detection"].(map[string]interface{}); ok {
		if enabled, ok := techDetection["enabled"].(bool); ok {
			p.techDetection = enabled
		}
	}

	if templatePriority, ok := config["template_prioritization"].(map[string]interface{}); ok {
		if enabled, ok := templatePriority["enabled"].(bool); ok {
			p.templatePriority = enabled
		}
	}

	if feedbackCollection, ok := config["feedback_collection"].(map[string]interface{}); ok {
		if enabled, ok := feedbackCollection["enabled"].(bool); ok {
			p.feedbackCollection = enabled
		}
	}

	return nil
}

// Start starts the plugin
func (p *Plugin) Start() error {
	fmt.Println("[Adaptive] Plugin started")
	return nil
}

// Stop stops the plugin
func (p *Plugin) Stop() error {
	fmt.Println("[Adaptive] Plugin stopped")
	return nil
}

// Hooks returns a map of hook functions that the plugin provides
func (p *Plugin) Hooks() map[string]interface{} {
	return map[string]interface{}{
		"post_target_load":        p.detectTechStack,
		"pre_template_execution":  p.prioritizeTemplates,
		"post_template_execution": p.collectFeedback,
	}
}

// detectTechStack detects the technology stack of a target
func (p *Plugin) detectTechStack(target *target.Target) {
	if !p.techDetection {
		return
	}

	fmt.Printf("[Adaptive] Detecting technology stack for %s\n", target.URL)

	// This is a simplified implementation
	// In a real implementation, this would perform technology detection
	// based on HTTP headers, response content, etc.

	// Create a new tech stack for the target
	techStack := &TechStack{
		Target:       target.URL,
		Technologies: make(map[string]float64),
	}

	// Simulate technology detection based on hostname
	hostname := strings.ToLower(target.Hostname)
	
	// Check for common technologies in hostname
	if strings.Contains(hostname, "wordpress") || strings.Contains(hostname, "wp") {
		techStack.Technologies["wordpress"] = 0.9
		techStack.Technologies["php"] = 0.8
	} else if strings.Contains(hostname, "joomla") {
		techStack.Technologies["joomla"] = 0.9
		techStack.Technologies["php"] = 0.8
	} else if strings.Contains(hostname, "drupal") {
		techStack.Technologies["drupal"] = 0.9
		techStack.Technologies["php"] = 0.8
	} else if strings.Contains(hostname, "django") {
		techStack.Technologies["django"] = 0.9
		techStack.Technologies["python"] = 0.8
	} else if strings.Contains(hostname, "rails") {
		techStack.Technologies["rails"] = 0.9
		techStack.Technologies["ruby"] = 0.8
	} else if strings.Contains(hostname, "node") {
		techStack.Technologies["nodejs"] = 0.9
		techStack.Technologies["javascript"] = 0.8
	} else if strings.Contains(hostname, "spring") {
		techStack.Technologies["spring"] = 0.9
		techStack.Technologies["java"] = 0.8
	} else {
		// Default technologies
		techStack.Technologies["http"] = 0.5
		techStack.Technologies["unknown"] = 0.5
	}

	// Store the tech stack
	p.mutex.Lock()
	p.techStack[target.URL] = techStack
	p.mutex.Unlock()

	fmt.Printf("[Adaptive] Detected technologies for %s: %v\n", target.URL, techStack.Technologies)
}

// prioritizeTemplates prioritizes templates based on the target's technology stack
func (p *Plugin) prioritizeTemplates(target *target.Target, templates []*template.Template) []*template.Template {
	if !p.templatePriority {
		return templates
	}

	fmt.Printf("[Adaptive] Prioritizing templates for %s\n", target.URL)

	// Get the target's tech stack
	p.mutex.RLock()
	techStack, ok := p.techStack[target.URL]
	p.mutex.RUnlock()

	if !ok {
		// No tech stack detected, return templates as-is
		return templates
	}

	// Create a map of template scores
	scores := make(map[string]float64)
	for _, tmpl := range templates {
		score := 0.0

		// Check if template tags match detected technologies
		for _, tag := range tmpl.Info.Tags {
			tag = strings.ToLower(tag)
			if confidence, ok := techStack.Technologies[tag]; ok {
				score += confidence
			}
		}

		// Check template stats for success rate
		p.mutex.RLock()
		if stats, ok := p.templateStats[tmpl.ID]; ok && stats.Executions > 0 {
			score += stats.SuccessRate * 0.5 // Weight success rate less than tech match
		}
		p.mutex.RUnlock()

		scores[tmpl.ID] = score
	}

	// Sort templates by score (higher scores first)
	// This is a simplified implementation using a bubble sort
	// In a real implementation, a more efficient sorting algorithm would be used
	for i := 0; i < len(templates)-1; i++ {
		for j := 0; j < len(templates)-i-1; j++ {
			if scores[templates[j].ID] < scores[templates[j+1].ID] {
				templates[j], templates[j+1] = templates[j+1], templates[j]
			}
		}
	}

	return templates
}

// collectFeedback collects feedback on template execution
func (p *Plugin) collectFeedback(target *target.Target, tmpl *template.Template, matched bool) {
	if !p.feedbackCollection {
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Get or create template stats
	stats, ok := p.templateStats[tmpl.ID]
	if !ok {
		stats = &TemplateStats{
			TemplateID: tmpl.ID,
			Tags:       tmpl.Info.Tags,
		}
		p.templateStats[tmpl.ID] = stats
	}

	// Update stats
	stats.Executions++
	if matched {
		stats.Matches++
	}
	stats.SuccessRate = float64(stats.Matches) / float64(stats.Executions)

	fmt.Printf("[Adaptive] Updated stats for template %s: executions=%d, matches=%d, success_rate=%.2f\n",
		tmpl.ID, stats.Executions, stats.Matches, stats.SuccessRate)
}

// GetTechStack returns the detected technology stack for a target
func (p *Plugin) GetTechStack(targetURL string) *TechStack {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.techStack[targetURL]
}

// GetTemplateStats returns the statistics for a template
func (p *Plugin) GetTemplateStats(templateID string) *TemplateStats {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.templateStats[templateID]
}

// GetAllTemplateStats returns statistics for all templates
func (p *Plugin) GetAllTemplateStats() map[string]*TemplateStats {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	// Create a copy to avoid concurrent access issues
	stats := make(map[string]*TemplateStats)
	for id, templateStats := range p.templateStats {
		stats[id] = templateStats
	}
	
	return stats
}
