package analyzer

// Findings represents all the discovered sensitive information
type Findings struct {
	Endpoints           []string `json:"endpoints"`
	Domains             []string `json:"domains"`
	SpecificAPIKeys     []string `json:"specific_api_keys"`
	GenericTokensKeys   []string `json:"generic_tokens_keys"`
	Credentials         []string `json:"credentials"`
	CreditCardNumbers   []string `json:"credit_card_numbers"`
	PrivateKeys         []string `json:"private_keys"`
	PublicKeys          []string `json:"public_keys"`
	Cookies             []string `json:"cookies"`
	SessionsStorage     []string `json:"sessions_storage"`
	IPAddresses         []string `json:"ip_addresses"`
	Base64EncodedStrings []string `json:"base64_encoded_strings"`
	Comments            []string `json:"comments"`
}

// NewFindings creates a new Findings instance with initialized slices
func NewFindings() *Findings {
	return &Findings{
		Endpoints:           make([]string, 0),
		Domains:             make([]string, 0),
		SpecificAPIKeys:     make([]string, 0),
		GenericTokensKeys:   make([]string, 0),
		Credentials:         make([]string, 0),
		CreditCardNumbers:   make([]string, 0),
		PrivateKeys:         make([]string, 0),
		PublicKeys:          make([]string, 0),
		Cookies:             make([]string, 0),
		SessionsStorage:     make([]string, 0),
		IPAddresses:         make([]string, 0),
		Base64EncodedStrings: make([]string, 0),
		Comments:            make([]string, 0),
	}
}

// TotalCount returns the total number of findings across all categories
func (f *Findings) TotalCount() int {
	return len(f.Endpoints) + len(f.Domains) + len(f.SpecificAPIKeys) + 
		   len(f.GenericTokensKeys) + len(f.Credentials) + len(f.CreditCardNumbers) + 
		   len(f.PrivateKeys) + len(f.PublicKeys) + len(f.Cookies) + 
		   len(f.SessionsStorage) + len(f.IPAddresses) + len(f.Base64EncodedStrings) + 
		   len(f.Comments)
}

// HasSensitiveData returns true if any sensitive data (excluding comments) was found
func (f *Findings) HasSensitiveData() bool {
	return len(f.Endpoints) > 0 || len(f.Domains) > 0 || len(f.SpecificAPIKeys) > 0 ||
		   len(f.GenericTokensKeys) > 0 || len(f.Credentials) > 0 || len(f.CreditCardNumbers) > 0 ||
		   len(f.PrivateKeys) > 0 || len(f.PublicKeys) > 0 || len(f.Cookies) > 0 ||
		   len(f.SessionsStorage) > 0 || len(f.IPAddresses) > 0 || len(f.Base64EncodedStrings) > 0
}

// SensitiveCount returns the count of sensitive findings (excluding comments)
func (f *Findings) SensitiveCount() int {
	return len(f.Endpoints) + len(f.Domains) + len(f.SpecificAPIKeys) + 
		   len(f.GenericTokensKeys) + len(f.Credentials) + len(f.CreditCardNumbers) + 
		   len(f.PrivateKeys) + len(f.PublicKeys) + len(f.Cookies) + 
		   len(f.SessionsStorage) + len(f.IPAddresses) + len(f.Base64EncodedStrings)
}
