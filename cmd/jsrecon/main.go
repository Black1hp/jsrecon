package main

import (
	"fmt"
	"os"

	"github.com/black1hp/jsrecon/internal/analyzer"
	"github.com/black1hp/jsrecon/internal/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version     = "1.0"
	author      = "Black1hp"
	githubURL   = "github.com/black1hp"
	outputFile  string
	verbose     bool
	debug       bool
	onlySecrets bool
	jsonOutput  bool
)

var rootCmd = &cobra.Command{
	Use:   "jsrecon",
	Short: "JSRecon - JavaScript Reconnaissance & Analysis Toolkit",
	Long: fmt.Sprintf(`╔══════════════════════════════════════════════════════════════════════════════════════════════╗
║                              JSRecon v%s                                                   ║
║                    JavaScript Reconnaissance & Analysis Toolkit                          ║
║                                                                                          ║
║                            Author: %s | %s                        ║
╚══════════════════════════════════════════════════════════════════════════════════════════════╝

JSRecon is a powerful tool for analyzing JavaScript files to identify:
• API endpoints and sensitive file paths
• Domain names and cloud storage URIs  
• API keys and authentication tokens
• Hardcoded credentials and secrets
• Private/public keys and certificates
• IP addresses and base64 encoded strings
• Session storage and cookie references
• Code comments with potential intel

Perfect for bug bounty hunters, penetration testers, and red team operations.`, version, author, githubURL),
	Example: `  # Analyze a single JavaScript file
  jsrecon analyze app.js

  # Analyze with verbose output
  jsrecon analyze app.js --verbose

  # Save results to file
  jsrecon analyze app.js --output results.txt

  # JSON output for automation
  jsrecon analyze app.js --json

  # Only show secrets and sensitive data
  jsrecon analyze app.js --secrets-only`,
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [file]",
	Short: "Analyze a JavaScript file for sensitive information",
	Args:  cobra.ExactArgs(1),
	Run:   runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")

	// Analyze command flags
	analyzeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file to save results")
	analyzeCmd.Flags().BoolVarP(&onlySecrets, "secrets-only", "s", false, "Only show secrets and sensitive information")
	analyzeCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output results in JSON format")

	// Bind flags to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("output", analyzeCmd.Flags().Lookup("output"))
	viper.BindPFlag("secrets-only", analyzeCmd.Flags().Lookup("secrets-only"))
	viper.BindPFlag("json", analyzeCmd.Flags().Lookup("json"))
}

func runAnalyze(cmd *cobra.Command, args []string) {
	filePath := args[0]

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: File '%s' not found\n", filePath)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Analyzing file: %s\n", filePath)
		fmt.Println("Starting analysis...")
	}

	// Create analyzer instance
	jsAnalyzer := analyzer.New()

	// Analyze the file
	findings, err := jsAnalyzer.AnalyzeFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing file: %v\n", err)
		os.Exit(1)
	}

	// Create output formatter
	formatter := output.NewFormatter(jsonOutput, onlySecrets, verbose)

	// Format the output
	result := formatter.Format(filePath, findings)

	// Output results
	if outputFile != "" {
		if err := output.WriteToFile(outputFile, result); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		if verbose {
			fmt.Printf("Results saved to: %s\n", outputFile)
		}
	} else {
		fmt.Print(result)
	}

	if verbose && !jsonOutput {
		fmt.Printf("\n[INFO] Analysis completed. Found %d total items across all categories.\n", findings.TotalCount())
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

