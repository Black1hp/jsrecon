package analyzer

import "regexp"

// CompiledPatterns holds all pre-compiled regex patterns for performance
type CompiledPatterns struct {
	Endpoints           *regexp.Regexp
	Domains             *regexp.Regexp
	SpecificAPIKeys     *regexp.Regexp
	GenericTokensKeys   *regexp.Regexp
	Credentials         *regexp.Regexp
	CreditCardNumbers   *regexp.Regexp
	PrivateKeys         *regexp.Regexp
	PublicKeys          *regexp.Regexp
	Cookies             *regexp.Regexp
	SessionsStorage     *regexp.Regexp
	IPAddresses         *regexp.Regexp
	Base64EncodedStrings *regexp.Regexp
	Comments            *regexp.Regexp
}

// CompilePatterns compiles all regex patterns and returns a CompiledPatterns struct
func CompilePatterns() *CompiledPatterns {
	return &CompiledPatterns{
		// 1. Endpoints & Sensitive File Paths
		// Captures API endpoints, backend file paths, generic URLs, sensitive file extensions with paths, and admin panel paths
		Endpoints: regexp.MustCompile(`(?i)` + 
			`["'](?:/?(?:api|v\d+)/(?:[\w\-\./%]+?)(?:\?(?:[\w\-\./%=&]+)?)?)["|']|` + // API endpoints
			`["'](?:/?[\w\-\./%]+?\.(?:json|xml|php|asp|aspx|jsp|do|action|svc|py|cgi|pl|rb|groovy|graphql))["|']|` + // Backend files
			`["'](?:https?:\/\/(?:[\w.-]+)?(?:\:\d+)?(?:/[\w\-\./%?=&]*)+?)["|']|` + // URLs
			`["'](?:[\w\-\./]+\.(?:js|xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|tmp|crt|pem|key|pub|asc))["|']|` +
			`(?:"|')?([\w\-\./]+\.(?:sql|db|backup|yml|yaml|env|key|pem|crt|asc|conf|config|ini))["|']?|` + // Sensitive files
			`(?:"|')/(?:admin|dashboard|control|panel)/[\w\-\./%]+?(?:"|')`), // Admin panels

		// 2. Domains/URLs
		// Captures general URLs, AWS S3 buckets, Azure Blob Storage, DigitalOcean Spaces, and cloud storage URIs
		Domains: regexp.MustCompile(`(?i)` +
			`(?:https?://|www\.)([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/\S*)?)|` + // General URLs
			`([a-zA-Z0-9_-]+\.s3[.-][a-zA-Z0-9_-]+\.amazonaws\.com)|` + // AWS S3 Buckets
			`s3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com|` +
			`s3://[a-zA-Z0-9-\._]+|` +
			`s3-[a-zA-Z0-9-\._/]+|` +
			`s3\.amazonaws\.com/[a-zA-Z0-9-\._]+|` +
			`s3\.console\.aws\.amazon\.com/s3/buckets/[a-zA-Z0-9-\._]+|` +
			`([a-zA-Z0-9_-]+\.blob\.core\.windows\.net)|` + // Azure Blob Storage
			`([a-zA-Z0-9_-]+\.digitaloceanspaces\.com)|` + // DigitalOcean Spaces
			`DefaultEndpointsProtocol=https;AccountName=([a-zA-Z0-9_-]+);AccountKey=([A-Za-z0-9/+=]+);EndpointSuffix=core\.windows\.net|` +
			`(gs://[a-zA-Z0-9_\-\.]+[/])|` + // Google Cloud Storage
			`([a-zA-Z0-9_\-\.]+\.storage\.googleapis\.com)|` +
			`(storage\.googleapis\.com/[\w\-\./%]+\?(?:X-Goog-Signature|GoogleAccessId|Expires|Signature)[^"'\s]*)`),

		// 3. Specific API Keys (High Confidence)
		// Matches patterns for well-known API keys and tokens with high precision
		SpecificAPIKeys: regexp.MustCompile(`(?i)` +
			`(AKIA[0-9A-Z]{16})|` + // AWS Access Keys
			`(ASIA[0-9A-Z]{16})|` +
			`(AZIA[0-9A-Z]{16})|` +
			`(AUZA[0-9A-Z]{16})|` +
			`(AIza[a-zA-Z0-9+_-]{35,})|` + // Google API Key
			`(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})|` + // Firebase Server Key
			`(6L[0-9A-Za-z-_]{38})|` + // Google Captcha
			`(6[0-9a-zA-Z_-]{39})|` +
			`(ya29\.[0-9A-Za-z\-_]{100,})|` + // Google OAuth
			`(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})|` + // Amazon MWS
			`(EAACEdEose0cBA[0-9A-Za-z]+)|` + // Facebook Access Token
			`(?:[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['"\\s])([0-9a-f]{32})['"\\s]|` + // Facebook
			`(?:[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['"\\s])([0-9a-zA-Z]{35,44})['"\\s]|` + // Twitter
			`(key-[0-9a-zA-Z]{32})|` + // Mailgun API Key
			`(SK[0-9a-fA-F]{32})|` + // Twilio Keys
			`(AC[a-zA-Z0-9_\-]{32})|` +
			`(AP[a-zA-Z0-9_\-]{32})|` +
			`(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})|` + // PayPal/Braintree
			`(sq0csp-[0-9A-Za-z\-_]{43})|` + // Square OAuth Secret
			`(sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43})|` +
			`(sqOatp-[0-9A-Za-z\-_]{22})|` + // Square Access Token
			`(EAAA[a-zA-Z0-9]{60})|` +
			`(sk_live_[0-9a-zA-Z]{24})|` + // Stripe Keys
			`(rk_live_[0-9a-zA-Z]{24})|` +
			`(pk_live_[0-9a-zA-Z]{24})|` +
			`(ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)|` + // JWT
			`(xox[pboar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})|` + // Slack Token
			`(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})|` + // Slack Webhook
			`([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})|` + // Heroku API Key
			`(?:[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}['"\\s])([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['"\\s]|` + // Heroku
			`([0-9a-f]{32}-us[0-9]{1,2})|` + // Mailchimp API key
			`(?:[a-zA-Z0-9_-]{2,}:\s*)?(ghp_[a-zA-Z0-9]{30,})|` + // GitHub Personal Access Token
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(AKIA[0-9A-Z]{16})(?:"|')|` + // Contextual AWS
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(ASIA[0-9A-Z]{16})(?:"|')|` +
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(AIza[0-9A-Za-z-_]{35})(?:"|')|` + // Google API Key contextual
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(v1\.0-[a-f0-9]{40})(?:"|')|` + // Cloudflare API Token
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(glpat-[A-Za-z0-9_-]{20})(?:"|')|` + // GitLab PAT
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(shpat_[a-f0-9]{32})(?:"|')|` + // Shopify Private App Token
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(vercel_[a-zA-Z0-9_-]{24})(?:"|')|` + // Vercel API Token
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(sk_live_[0-9a-zA-Z]{24})(?:"|')|` + // Stripe Secret Key
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(xox[a-zA-Z]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})(?:"|')|` + // Slack Token
			`(?:api_key|secret|token)[:=]\s*(?:"|')?(ghp_[A-Za-z0-9]{36,40})(?:"|')|` + // GitHub PAT
			`(?:AWS_SECRET_ACCESS_KEY|awsSecretAccessKey|secretAccessKey)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?|` +
			`(?:AWS_SESSION_TOKEN|awsSessionToken|sessionToken)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?|` +
			`(?:firebase|FIREBASE)_(?:secret|token)\s*[:=]\s*['"]?([a-zA-Z0-9]{30,})['"]?|` +
			`(AC[a-zA-Z0-9_\-]{32}):([a-f0-9]{32})|` + // Twilio API Key format
			`(SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{22,})|` + // SendGrid API Key
			`(pk\.eyJ[a-zA-Z0-9\-_]{50,})|` + // Mapbox Access Token
			`(vercel_[a-zA-Z0-9_-]{24})|` +
			`([0-9A-Za-z_-]{42})|` + // Okta API Token
			`(shpss_[a-f0-9]{32})|` + // Shopify Shared Secret
			`(glrt-[A-Za-z0-9_-]{20})|` + // GitLab Runner Token
			`(NRAK-[A-Z0-9]{27})|` + // New Relic Admin Key
			`(eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)`), // Kubernetes JWT

		// 4. Generic Tokens/Keys - Extensive pattern list migrated from your Python tool
		GenericTokensKeys: regexp.MustCompile(`(?i)` +
			`(?:private[_-]?api[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:token[_-]?pem)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:api[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:auth[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:access[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:client[_-]?id)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:refresh[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:oauth[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:jwt[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:vpn[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:encryption[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:database[_-]?password)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:admin[_-]?password)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:user[_-]?password)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:service[_-]?account[_-]?password)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:public[_-]?api[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:webhook[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:webhook[_-]?secret)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:smtp[_-]?password)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:ftp[_-]?password)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:ldap[_-]?password)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:secret[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:github[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:gitlab[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:slack[_-]?api[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:twilio[_-]?auth[_-]?token)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:sendgrid[_-]?api[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:private[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:ssh[_-]?key)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`(?:root[_-]?password)\s*[:=]\s*(?:"|')?([a-zA-Z0-9_\-]{8,})(?:"|')?|` +
			`([A-Za-z0-9/+=]{40})|` + // Generic AWS-style keys
			`([A-Za-z0-9/+=]{100,})|` + // Generic long tokens
			`([a-z0-9]{30})|` + // Generic 30-char tokens  
			`([a-f0-9]{64})|` + // Generic 64-char hex
			`([a-f0-9]{32})|` + // Generic 32-char hex
			`([a-f0-9]{40})`), // Generic 40-char hex

		// 5. Hardcoded Credentials
		Credentials: regexp.MustCompile(`(?i)` +
			`(?:user(?:name)?|login|usr|uid)(?:"|')?\s*[:=]\s*(?:"|')?([a-zA-Z0-9_.\-]+)(?:"|')?|` + // Username
			`(?:email)[:=]\s*(?:"|')?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:"|')?|` + // Email
			`(?:pass(?:word)?|pwd|secret|cred)[:=]\s*(?:"|')?([a-zA-Z0-9_.\-@!#$%&*]{8,})(?:"|')?|` + // Password
			`https?:\/\/(?:[a-zA-Z0-9_-]+):([a-zA-Z0-9_\-]+)@github\.com(?:[\s'"/]|$)|` + // GitHub token in URL
			`(mongodb|postgresql|mysql)://[a-zA-Z0-9_-]+:[a-zA-Z0-9_\-\.@!#$%&*]+@[a-zA-Z0-9.-]+(?::\d+)?/[a-zA-Z0-9_-]+|` + // Database URIs
			`["'](?:admin|root|user|test|dev)[:=](?:admin|root|user|test|dev|password|secret)["']`), // Default credentials

		// 6. Credit Card Numbers & SSN
		CreditCardNumbers: regexp.MustCompile(`(?i)` +
			`(4[0-9]{12}(?:[0-9]{3})?)|` + // Visa
			`(5[1-5][0-9]{14})|` + // Mastercard
			`(3[47][0-9]{13})|` + // Amex
			`(3(?:0[0-5]|[68][0-9])[0-9]{11})|` + // Diners Club, Carte Blanche
			`(6(?:011|5[0-9]{2})[0-9]{12})|` + // Discover
			`(ssn[^\w\n]*\d{3}[ -]?\d{2}[ -]?\d{4})`), // SSN pattern

		// 7. Private Keys
		PrivateKeys: regexp.MustCompile(`(?ms)` +
			`([-]+BEGIN (?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP|PRIVATE) KEY(?: BLOCK)?[-]+[\s\S]*?[-]+END (?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP|PRIVATE) KEY(?: BLOCK)?[-]+)`),

		// 8. Public Keys
		PublicKeys: regexp.MustCompile(`(?i)` +
			`(ssh-rsa\s+[A-Za-z0-9+/=]+)`),

		// 9. Cookies
		Cookies: regexp.MustCompile(`(?i)` +
			`(?:document\.cookie|(?:"|')(?:sessionid|PHPSESSID|JSESSIONID|__Host-|__Secure-|_ga|_gid|auth_token|remember_me)\s*[:=])`),

		// 10. Session Storage/Local Storage
		SessionsStorage: regexp.MustCompile(`(?i)` +
			`(?:(?:session|local)Storage\.(?:getItem|setItem|removeItem|clear)|(?:session|local)ID|user_session|AUTH_SESSION|id_token|access_token|user_profile_data)`),

		// 11. IP Addresses
		IPAddresses: regexp.MustCompile(`(?i)` +
			`(?!(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.))((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b|` + // Public IPv4
			`\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b|` + // Any IPv4
			`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|` + // IPv6 full
			`\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b`), // IPv6 abbreviated

		// 12. Base64 Encoded Strings
		Base64EncodedStrings: regexp.MustCompile(`(?i)` +
			`(eyJ|YTo|Tzo|PD|rO0)([a-zA-Z0-9+/=]{20,})`),

		// 13. Comments
		Comments: regexp.MustCompile(`(?ms)` +
			`//.*?$|/\*.*?\*/`),
	}
}
