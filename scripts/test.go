package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dejavu/scanner/internal/config"
	"github.com/dejavu/scanner/pkg/adaptive"
	"github.com/dejavu/scanner/pkg/core/engine"
	"github.com/dejavu/scanner/pkg/persona"
	"github.com/dejavu/scanner/pkg/timetravel"
)

func main() {
	// Create a sample template for testing
	createSampleTemplate()

	// Create a test script to verify Deja Vu functionality
	fmt.Println("=== Deja Vu Test Script ===")
	
	// Load configuration
	fmt.Println("Loading configuration...")
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}
	
	// Enable all features for testing
	cfg.Features.TimeTravel.Enabled = true
	cfg.Features.Persona.Enabled = true
	cfg.Features.Adaptive.Enabled = true
	
	// Initialize scanner
	fmt.Println("Initializing scanner...")
	scanner, err := engine.NewScanner(cfg)
	if err != nil {
		fmt.Printf("Error initializing scanner: %v\n", err)
		os.Exit(1)
	}
	
	// Register plugins
	fmt.Println("Registering plugins...")
	
	// Register time travel plugin
	err = timetravel.RegisterPlugin(scanner, cfg)
	if err != nil {
		fmt.Printf("Error registering time travel plugin: %v\n", err)
		os.Exit(1)
	}
	
	// Register persona plugin
	err = persona.RegisterPlugin(scanner, cfg)
	if err != nil {
		fmt.Printf("Error registering persona plugin: %v\n", err)
		os.Exit(1)
	}
	
	// Register adaptive learning plugin
	err = adaptive.RegisterPlugin(scanner, cfg)
	if err != nil {
		fmt.Printf("Error registering adaptive learning plugin: %v\n", err)
		os.Exit(1)
	}
	
	// Test different personas
	testPersonas := []string{"standard", "stealthy", "aggressive", "apt"}
	for _, personaName := range testPersonas {
		fmt.Printf("\n=== Testing with %s persona ===\n", personaName)
		
		// Set persona
		cfg.Features.Persona.DefaultPersona = personaName
		
		// Define test target
		target := "example.com"
		fmt.Printf("Running scan against test target: %s\n", target)
		
		// Run scan
		err = scanner.Scan(target)
		if err != nil {
			fmt.Printf("Error during scan: %v\n", err)
			continue
		}
		
		fmt.Printf("Scan with %s persona completed successfully!\n", personaName)
	}
	
	// Test time travel feature
	fmt.Println("\n=== Testing Time Travel feature ===")
	target := "wordpress.org"
	fmt.Printf("Running time travel scan against: %s\n", target)
	
	// Run scan
	err = scanner.Scan(target)
	if err != nil {
		fmt.Printf("Error during time travel scan: %v\n", err)
	} else {
		fmt.Println("Time travel scan completed successfully!")
	}
	
	// Test adaptive learning feature
	fmt.Println("\n=== Testing Adaptive Learning feature ===")
	targets := []string{"wordpress.com", "drupal.org", "joomla.org"}
	for _, target := range targets {
		fmt.Printf("Running adaptive scan against: %s\n", target)
		
		// Run scan
		err = scanner.Scan(target)
		if err != nil {
			fmt.Printf("Error during adaptive scan: %v\n", err)
			continue
		}
		
		fmt.Printf("Adaptive scan of %s completed successfully!\n", target)
	}
	
	fmt.Println("\n=== Test Script Completed ===")
}

// createSampleTemplate creates a sample template for testing
func createSampleTemplate() {
	// Create templates directory if it doesn't exist
	templatesDir := "templates"
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		os.Mkdir(templatesDir, 0755)
	}
	
	// Create a sample template
	sampleTemplate := `
id: test-template
info:
  name: Test Template
  author: Deja Vu
  description: A test template for Deja Vu
  severity: info
  tags:
    - test
    - http

requests:
  - method: GET
    path: /
    headers:
      User-Agent: Deja Vu Test
    matchers:
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: body
        name: title
        regex:
          - "<title>(.*?)</title>"
`
	
	// Write the template to a file
	templatePath := filepath.Join(templatesDir, "test-template.yaml")
	err := os.WriteFile(templatePath, []byte(sampleTemplate), 0644)
	if err != nil {
		fmt.Printf("Error creating sample template: %v\n", err)
	} else {
		fmt.Printf("Created sample template: %s\n", templatePath)
	}
}
