package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/black1hp/jsrecon/internal/analyzer"
)

// Formatter handles output formatting
type Formatter struct {
	jsonOutput   bool
	secretsOnly  bool
	verbose      bool
}

// NewFormatter creates a new Formatter instance
func NewFormatter(jsonOutput, secretsOnly, verbose bool) *Formatter {
	return &Formatter{
		jsonOutput:  jsonOutput,
		secretsOnly: secretsOnly,
		verbose:     verbose,
	}
}

// Format formats the findings according to the specified options
func (f *Formatter) Format(filePath string, findings *analyzer.Findings) string {
	if f.jsonOutput {
		return f.formatJSON(filePath, findings)
	}
	return f.formatText(filePath, findings)
}

// formatJSON formats findings as JSON
func (f *Formatter) formatJSON(filePath string, findings *analyzer.Findings) string {
	result := map[string]interface{}{
		"file":     filePath,
		"findings": findings,
		"summary": map[string]interface{}{
			"total_count":     findings.TotalCount(),
			"sensitive_count": findings.SensitiveCount(),
			"has_sensitive":   findings.HasSensitiveData(),
		},
	}

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "Failed to marshal JSON: %s"}`, err.Error())
	}

	return string(jsonBytes)
}

// formatText formats findings as human-readable text
func (f *Formatter) formatText(filePath string, findings *analyzer.Findings) string {
	var output strings.Builder

	// Header
	output.WriteString(fmt.Sprintf("\n╔══════════════════════════════════════════════════════════════════════════════════════════════╗\n"))
	output.WriteString(fmt.Sprintf("║                              JSRecon Analysis Report                                        ║\n"))
	output.WriteString(fmt.Sprintf("║                            Author: Black1hp | github.com/black1hp                       ║\n"))
	output.WriteString(fmt.Sprintf("╚══════════════════════════════════════════════════════════════════════════════════════════════╝\n"))
	output.WriteString(fmt.Sprintf("\n🎯 Target: %s\n", filePath))

	// Check if any sensitive data was found
	if findings.HasSensitiveData() {
		output.WriteString(fmt.Sprintf("\n🚨 [SENSITIVE INFORMATION DETECTED] - %d items found\n", findings.SensitiveCount()))

		// Endpoints & Sensitive File Paths
		if len(findings.Endpoints) > 0 {
			f.addSection(&output, "🌐 Endpoints & Sensitive File Paths", findings.Endpoints, "Potential API endpoints, backend files, and sensitive paths")
		}

		// Domains/URLs
		if len(findings.Domains) > 0 {
			f.addSection(&output, "🔗 Domains/URLs (including Cloud Storage)", findings.Domains, "External domains, cloud storage URIs, and CDN links")
		}

		// Specific API Keys (High Confidence)
		if len(findings.SpecificAPIKeys) > 0 {
			f.addSection(&output, "🔑 Specific API Keys (High Confidence)", findings.SpecificAPIKeys, "Well-known API key patterns - HIGH PRIORITY!")
		}

		// Generic Tokens/Keys
		if len(findings.GenericTokensKeys) > 0 && !f.secretsOnly {
			f.addSection(&output, "⚠️  Generic Tokens/Keys (Manual Review Required)", findings.GenericTokensKeys, "Broad patterns that might be tokens/keys - verify manually")
		}

		// Hardcoded Credentials
		if len(findings.Credentials) > 0 {
			f.addSection(&output, "👤 Hardcoded Credentials", findings.Credentials, "Usernames, passwords, and database connection strings")
		}

		// Credit Card Numbers/SSN
		if len(findings.CreditCardNumbers) > 0 {
			f.addSection(&output, "💳 Credit Card Numbers / SSN Patterns", findings.CreditCardNumbers, "Payment card data and SSN patterns - validate manually")
		}

		// Private Keys
		if len(findings.PrivateKeys) > 0 {
			f.addSection(&output, "🔐 Private Key Blocks", findings.PrivateKeys, "HIGHLY SENSITIVE - Private cryptographic keys")
		}

		// Public Keys
		if len(findings.PublicKeys) > 0 && !f.secretsOnly {
			f.addSection(&output, "🔓 Public Keys", findings.PublicKeys, "SSH and cryptographic public keys")
		}

		// Cookies
		if len(findings.Cookies) > 0 && !f.secretsOnly {
			f.addSection(&output, "🍪 Cookie References", findings.Cookies, "Session cookies and authentication tokens")
		}

		// Session/Local Storage
		if len(findings.SessionsStorage) > 0 && !f.secretsOnly {
			f.addSection(&output, "💾 Session/Storage References", findings.SessionsStorage, "Browser storage access patterns")
		}

		// IP Addresses
		if len(findings.IPAddresses) > 0 && !f.secretsOnly {
			f.addSection(&output, "🌍 IP Addresses", findings.IPAddresses, "Network addresses and infrastructure")
		}

		// Base64 Encoded Strings
		if len(findings.Base64EncodedStrings) > 0 && !f.secretsOnly {
			f.addSection(&output, "📦 Base64 Encoded Strings", findings.Base64EncodedStrings, "Potentially encoded secrets or data")
		}
	} else {
		output.WriteString("\n✅ No sensitive information patterns detected (excluding comments).\n")
	}

	// Comments (always show unless secrets-only mode)
	if len(findings.Comments) > 0 && !f.secretsOnly {
		f.addSection(&output, "💬 Comments (Review for Intel)", findings.Comments, "Code comments that may contain sensitive information")
	} else if !f.secretsOnly {
		output.WriteString("\n💬 No comments found.\n")
	}

	// Footer
	output.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("─", 100)))
	output.WriteString("⚠️  IMPORTANT: This tool uses heuristic regex patterns. Always perform manual review.\n")
	output.WriteString("   False positives are expected. Context is key for validation.\n")
	output.WriteString("   Author: Black1hp | github.com/black1hp\n")
	output.WriteString(fmt.Sprintf("%s\n", strings.Repeat("─", 100)))

	return output.String()
}

// addSection adds a formatted section to the output
func (f *Formatter) addSection(output *strings.Builder, title string, items []string, description string) {
	output.WriteString(fmt.Sprintf("\n%s (%d items)\n", title, len(items)))
	if f.verbose {
		output.WriteString(fmt.Sprintf("   %s\n", description))
	}
	output.WriteString(strings.Repeat("─", len(title)+20) + "\n")

	for i, item := range items {
		if i < 10 || f.verbose { // Show first 10 items or all if verbose
			output.WriteString(fmt.Sprintf("  • %s\n", item))
		} else if i == 10 {
			output.WriteString(fmt.Sprintf("  ... and %d more items (use --verbose to see all)\n", len(items)-10))
			break
		}
	}
}
