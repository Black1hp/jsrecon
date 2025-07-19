package analyzer

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Analyzer handles JavaScript file analysis
type Analyzer struct {
	patterns *CompiledPatterns
}

// New creates a new Analyzer instance
func New() *Analyzer {
	return &Analyzer{
		patterns: CompilePatterns(),
	}
}

// AnalyzeFile analyzes a JavaScript file and returns findings
func (a *Analyzer) AnalyzeFile(filePath string) (*Findings, error) {
	// Read file content
	content, err := a.readFile(filePath)
	if err != nil {
		return nil, err
	}

	// Initialize findings
	findings := NewFindings()

	// Extract comments first, then remove them for main content analysis
	a.extractComments(content, findings)
	contentWithoutComments := a.patterns.Comments.ReplaceAllString(content, " ")

	// Apply all regex patterns to the content without comments
	a.extractEndpoints(contentWithoutComments, findings)
	a.extractDomains(contentWithoutComments, findings)
	a.extractSpecificAPIKeys(contentWithoutComments, findings)
	a.extractGenericTokensKeys(contentWithoutComments, findings)
	a.extractCredentials(contentWithoutComments, findings)
	a.extractCreditCardNumbers(contentWithoutComments, findings)
	a.extractPrivateKeys(contentWithoutComments, findings)
	a.extractPublicKeys(contentWithoutComments, findings)
	a.extractCookies(contentWithoutComments, findings)
	a.extractSessionsStorage(contentWithoutComments, findings)
	a.extractIPAddresses(contentWithoutComments, findings)
	a.extractBase64EncodedStrings(contentWithoutComments, findings)

	// Sort all findings for consistent output
	a.sortFindings(findings)

	return findings, nil
}

// readFile reads the content of a file with optimized buffer handling
func (a *Analyzer) readFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var content strings.Builder
	scanner := bufio.NewScanner(file)
	
	// Handle large files by increasing buffer size
	buffer := make([]byte, 1024*1024) // 1MB buffer
	scanner.Buffer(buffer, 10*1024*1024) // 10MB max token size
	
	for scanner.Scan() {
		content.WriteString(scanner.Text())
		content.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return content.String(), nil
}

// addMatchesToSlice helper function to find matches and add them to target slice with deduplication
func (a *Analyzer) addMatchesToSlice(pattern *regexp.Regexp, target *[]string, text string) {
	seenMatches := make(map[string]bool) // Deduplicate matches
	
	for _, match := range pattern.FindAllStringSubmatch(text, -1) {
		addedFromGroup := false
		
		// Check capturing groups first
		if len(match) > 1 {
			for i := 1; i < len(match); i++ {
				if match[i] != "" {
					cleanMatch := strings.TrimSpace(match[i])
					if cleanMatch != "" && !seenMatches[cleanMatch] {
						*target = append(*target, cleanMatch)
						seenMatches[cleanMatch] = true
						addedFromGroup = true
						break // Stop after finding the first relevant group
					}
				}
			}
		}
		
		// If no specific group was added, add the full match
		if !addedFromGroup && match[0] != "" {
			cleanMatch := strings.TrimSpace(match[0])
			if cleanMatch != "" && !seenMatches[cleanMatch] {
				*target = append(*target, cleanMatch)
				seenMatches[cleanMatch] = true
			}
		}
	}
}

// Extract methods for each pattern category
func (a *Analyzer) extractEndpoints(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.Endpoints, &findings.Endpoints, content)
}

func (a *Analyzer) extractDomains(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.Domains, &findings.Domains, content)
}

func (a *Analyzer) extractSpecificAPIKeys(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.SpecificAPIKeys, &findings.SpecificAPIKeys, content)
}

func (a *Analyzer) extractGenericTokensKeys(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.GenericTokensKeys, &findings.GenericTokensKeys, content)
}

func (a *Analyzer) extractCredentials(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.Credentials, &findings.Credentials, content)
}

func (a *Analyzer) extractCreditCardNumbers(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.CreditCardNumbers, &findings.CreditCardNumbers, content)
}

func (a *Analyzer) extractPrivateKeys(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.PrivateKeys, &findings.PrivateKeys, content)
}

func (a *Analyzer) extractPublicKeys(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.PublicKeys, &findings.PublicKeys, content)
}

func (a *Analyzer) extractCookies(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.Cookies, &findings.Cookies, content)
}

func (a *Analyzer) extractSessionsStorage(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.SessionsStorage, &findings.SessionsStorage, content)
}

func (a *Analyzer) extractIPAddresses(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.IPAddresses, &findings.IPAddresses, content)
}

func (a *Analyzer) extractBase64EncodedStrings(content string, findings *Findings) {
	a.addMatchesToSlice(a.patterns.Base64EncodedStrings, &findings.Base64EncodedStrings, content)
}

func (a *Analyzer) extractComments(content string, findings *Findings) {
	matches := a.patterns.Comments.FindAllString(content, -1)
	seenComments := make(map[string]bool)
	
	for _, comment := range matches {
		cleanComment := strings.TrimSpace(comment)
		if cleanComment != "" && !seenComments[cleanComment] {
			findings.Comments = append(findings.Comments, cleanComment)
			seenComments[cleanComment] = true
		}
	}
}

// sortFindings sorts all finding slices for consistent output
func (a *Analyzer) sortFindings(findings *Findings) {
	sort.Strings(findings.Endpoints)
	sort.Strings(findings.Domains)
	sort.Strings(findings.SpecificAPIKeys)
	sort.Strings(findings.GenericTokensKeys)
	sort.Strings(findings.Credentials)
	sort.Strings(findings.CreditCardNumbers)
	sort.Strings(findings.PrivateKeys)
	sort.Strings(findings.PublicKeys)
	sort.Strings(findings.Cookies)
	sort.Strings(findings.SessionsStorage)
	sort.Strings(findings.IPAddresses)
	sort.Strings(findings.Base64EncodedStrings)
	sort.Strings(findings.Comments)
}
