package main

import (
	"fmt"
	"os"

	"github.com/dejavu/scanner/internal/config"
	"github.com/dejavu/scanner/pkg/core/engine"
	"github.com/spf13/cobra"
)

var (
	targetFlag      string
	configFlag      string
	timeTravelFlag  bool
	personaFlag     string
	adaptiveFlag    bool
	templateDirFlag string
	outputFlag      string
	verboseFlag     bool
)

var rootCmd = &cobra.Command{
	Use:   "deja_vu",
	Short: "Deja Vu - Next-Generation Adaptive Vulnerability Scanner",
	Long: `Deja Vu is a next-generation vulnerability scanner that builds upon Nuclei's foundation
while incorporating advanced features for intelligent, context-aware security testing.

It extends traditional vulnerability scanning with:
- Time-Travel Scanning: Analyze historical versions of targets
- Personality-Driven Scanning: Emulate different attacker personas
- Adaptive Learning: Intelligently prioritize templates based on target technology`,
	Run: func(cmd *cobra.Command, args []string) {
		if targetFlag == "" {
			fmt.Println("Error: target is required")
			cmd.Help()
			os.Exit(1)
		}

		// Load configuration
		cfg, err := config.LoadConfig(configFlag)
		if err != nil {
			fmt.Printf("Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		// Override config with command line flags
		if timeTravelFlag {
			cfg.Features.TimeTravel.Enabled = true
		}
		if personaFlag != "" {
			cfg.Features.Persona.Enabled = true
			cfg.Features.Persona.DefaultPersona = personaFlag
		}
		if adaptiveFlag {
			cfg.Features.Adaptive.Enabled = true
		}
		if templateDirFlag != "" {
			cfg.Core.TemplateDir = templateDirFlag
		}
		if outputFlag != "" {
			cfg.Core.OutputFormat = outputFlag
		}
		if verboseFlag {
			cfg.Logging.Level = "debug"
		}

		// Initialize and run the scanner
		scanner, err := engine.NewScanner(cfg)
		if err != nil {
			fmt.Printf("Error initializing scanner: %v\n", err)
			os.Exit(1)
		}

		err = scanner.Scan(targetFlag)
		if err != nil {
			fmt.Printf("Error during scan: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.Flags().StringVarP(&targetFlag, "target", "t", "", "Target URL, IP, or domain to scan")
	rootCmd.Flags().StringVarP(&configFlag, "config", "c", "config.yaml", "Path to configuration file")
	rootCmd.Flags().BoolVar(&timeTravelFlag, "time-travel", false, "Enable time-travel scanning")
	rootCmd.Flags().StringVar(&personaFlag, "persona", "", "Use specific scanning persona")
	rootCmd.Flags().BoolVar(&adaptiveFlag, "adaptive", false, "Enable adaptive learning")
	rootCmd.Flags().StringVar(&templateDirFlag, "templates", "", "Path to template directory")
	rootCmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output format (json, yaml, cli)")
	rootCmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "Enable verbose logging")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
