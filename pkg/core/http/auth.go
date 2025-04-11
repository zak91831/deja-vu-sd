package http

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
)

// AuthType defines the type of authentication
type AuthType string

const (
	// BasicAuth represents HTTP Basic Authentication
	BasicAuth AuthType = "basic"
	
	// BearerAuth represents Bearer Token Authentication
	BearerAuth AuthType = "bearer"
	
	// DigestAuth represents HTTP Digest Authentication
	DigestAuth AuthType = "digest"
	
	// OAuthAuth represents OAuth Authentication
	OAuthAuth AuthType = "oauth"
	
	// CustomAuth represents a custom authentication method
	CustomAuth AuthType = "custom"
)

// AuthConfig contains authentication configuration
type AuthConfig struct {
	// Type is the authentication type
	Type AuthType
	
	// Username for Basic and Digest authentication
	Username string
	
	// Password for Basic and Digest authentication
	Password string
	
	// Token for Bearer authentication
	Token string
	
	// OAuthConfig for OAuth authentication
	OAuthConfig *OAuthConfig
	
	// CustomHeaders for custom authentication
	CustomHeaders map[string]string
	
	// CustomCookies for custom authentication
	CustomCookies []*http.Cookie
	
	// PreAuthHook is called before authentication
	PreAuthHook func(*http.Request) error
	
	// PostAuthHook is called after authentication
	PostAuthHook func(*http.Response) error
}

// OAuthConfig contains OAuth configuration
type OAuthConfig struct {
	// ClientID is the OAuth client ID
	ClientID string
	
	// ClientSecret is the OAuth client secret
	ClientSecret string
	
	// TokenURL is the URL to obtain tokens
	TokenURL string
	
	// AuthURL is the URL to authorize
	AuthURL string
	
	// RedirectURL is the redirect URL after authorization
	RedirectURL string
	
	// Scopes are the OAuth scopes to request
	Scopes []string
	
	// RefreshToken is the OAuth refresh token
	RefreshToken string
	
	// AccessToken is the OAuth access token
	AccessToken string
	
	// TokenType is the OAuth token type
	TokenType string
	
	// Expiry is the OAuth token expiry time
	Expiry int64
}

// Authenticator handles authentication for HTTP requests
type Authenticator struct {
	// Config is the authentication configuration
	Config *AuthConfig
	
	// Client is the HTTP client to use
	Client *http.Client
	
	// Session is the session to use for authentication
	Session *Session
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(config *AuthConfig, client *http.Client, session *Session) *Authenticator {
	return &Authenticator{
		Config:  config,
		Client:  client,
		Session: session,
	}
}

// ApplyAuth applies authentication to a request
func (a *Authenticator) ApplyAuth(req *http.Request) error {
	if a.Config == nil {
		return nil
	}
	
	// Call pre-auth hook if defined
	if a.Config.PreAuthHook != nil {
		if err := a.Config.PreAuthHook(req); err != nil {
			return err
		}
	}
	
	switch a.Config.Type {
	case BasicAuth:
		req.SetBasicAuth(a.Config.Username, a.Config.Password)
	
	case BearerAuth:
		req.Header.Set("Authorization", "Bearer "+a.Config.Token)
	
	case DigestAuth:
		// Digest auth requires a challenge-response flow
		// This is a simplified implementation
		if a.Session != nil {
			// Check if we have a nonce in the session
			if nonce, exists := a.Session.GetState("digest_nonce"); exists {
				// Create digest header
				digestHeader := createDigestHeader(
					req.Method,
					req.URL.Path,
					a.Config.Username,
					a.Config.Password,
					nonce.(string),
				)
				req.Header.Set("Authorization", digestHeader)
			}
		}
	
	case OAuthAuth:
		if a.Config.OAuthConfig != nil && a.Config.OAuthConfig.AccessToken != "" {
			tokenType := a.Config.OAuthConfig.TokenType
			if tokenType == "" {
				tokenType = "Bearer"
			}
			req.Header.Set("Authorization", tokenType+" "+a.Config.OAuthConfig.AccessToken)
		}
	
	case CustomAuth:
		// Apply custom headers
		for key, value := range a.Config.CustomHeaders {
			req.Header.Set(key, value)
		}
		
		// Apply custom cookies
		for _, cookie := range a.Config.CustomCookies {
			req.AddCookie(cookie)
		}
	}
	
	return nil
}

// HandleAuthResponse handles authentication-related responses
func (a *Authenticator) HandleAuthResponse(resp *http.Response) error {
	if a.Config == nil {
		return nil
	}
	
	// Call post-auth hook if defined
	if a.Config.PostAuthHook != nil {
		if err := a.Config.PostAuthHook(resp); err != nil {
			return err
		}
	}
	
	switch a.Config.Type {
	case DigestAuth:
		// Handle digest auth challenge
		if resp.StatusCode == http.StatusUnauthorized {
			authHeader := resp.Header.Get("WWW-Authenticate")
			if strings.HasPrefix(authHeader, "Digest") {
				// Parse nonce from header
				nonce := parseDigestNonce(authHeader)
				if nonce != "" && a.Session != nil {
					// Store nonce in session for next request
					a.Session.SetState("digest_nonce", nonce)
				}
			}
		}
	
	case OAuthAuth:
		// Handle OAuth token refresh
		if resp.StatusCode == http.StatusUnauthorized && a.Config.OAuthConfig != nil {
			// Attempt to refresh token
			if a.Config.OAuthConfig.RefreshToken != "" {
				// This would normally call the token endpoint
				// Simplified implementation
			}
		}
	}
	
	return nil
}

// RefreshOAuthToken refreshes an OAuth token
func (a *Authenticator) RefreshOAuthToken() error {
	if a.Config == nil || a.Config.Type != OAuthAuth || a.Config.OAuthConfig == nil {
		return nil
	}
	
	// This would normally call the token endpoint
	// Simplified implementation
	return nil
}

// createDigestHeader creates a digest authentication header
func createDigestHeader(method, uri, username, password, nonce string) string {
	// This is a simplified implementation
	// A real implementation would calculate proper MD5 hashes
	return "Digest username=\"" + username + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\"dummy\""
}

// parseDigestNonce parses the nonce from a digest authentication challenge
func parseDigestNonce(authHeader string) string {
	// This is a simplified implementation
	// A real implementation would properly parse the header
	if strings.Contains(authHeader, "nonce=\"") {
		parts := strings.Split(authHeader, "nonce=\"")
		if len(parts) > 1 {
			noncePart := parts[1]
			endQuote := strings.Index(noncePart, "\"")
			if endQuote > 0 {
				return noncePart[:endQuote]
			}
		}
	}
	return ""
}

// ProxyConfig contains proxy configuration
type ProxyConfig struct {
	// URL is the proxy URL
	URL string
	
	// Username for proxy authentication
	Username string
	
	// Password for proxy authentication
	Password string
	
	// NoProxy is a list of hosts to exclude from proxying
	NoProxy []string
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	// InsecureSkipVerify controls whether to verify server certificates
	InsecureSkipVerify bool
	
	// MinVersion is the minimum TLS version to use
	MinVersion uint16
	
	// MaxVersion is the maximum TLS version to use
	MaxVersion uint16
	
	// CipherSuites is the list of cipher suites to use
	CipherSuites []uint16
	
	// CertificatePath is the path to the client certificate
	CertificatePath string
	
	// KeyPath is the path to the client key
	KeyPath string
	
	// CAPath is the path to the CA certificate
	CAPath string
}

// CreateTLSConfig creates a TLS configuration
func CreateTLSConfig(config *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
	}
	
	if config.MinVersion > 0 {
		tlsConfig.MinVersion = config.MinVersion
	}
	
	if config.MaxVersion > 0 {
		tlsConfig.MaxVersion = config.MaxVersion
	}
	
	if len(config.CipherSuites) > 0 {
		tlsConfig.CipherSuites = config.CipherSuites
	}
	
	// Load client certificate if specified
	if config.CertificatePath != "" && config.KeyPath != "" {
		// In a real implementation, this would load the certificate and key
		// cert, err := tls.LoadX509KeyPair(config.CertificatePath, config.KeyPath)
		// if err != nil {
		//     return nil, err
		// }
		// tlsConfig.Certificates = []tls.Certificate{cert}
	}
	
	// Load CA certificate if specified
	if config.CAPath != "" {
		// In a real implementation, this would load the CA certificate
		// caCert, err := ioutil.ReadFile(config.CAPath)
		// if err != nil {
		//     return nil, err
		// }
		// caCertPool := x509.NewCertPool()
		// caCertPool.AppendCertsFromPEM(caCert)
		// tlsConfig.RootCAs = caCertPool
	}
	
	return tlsConfig, nil
}

// CreateProxyFunc creates a proxy function for http.Transport
func CreateProxyFunc(config *ProxyConfig) func(*http.Request) (*url.URL, error) {
	if config == nil || config.URL == "" {
		return http.ProxyFromEnvironment
	}
	
	proxyURL, err := url.Parse(config.URL)
	if err != nil {
		return http.ProxyFromEnvironment
	}
	
	// Add authentication if specified
	if config.Username != "" {
		proxyURL.User = url.UserPassword(config.Username, config.Password)
	}
	
	return func(req *http.Request) (*url.URL, error) {
		// Check if host should bypass proxy
		host := req.URL.Hostname()
		for _, noProxy := range config.NoProxy {
			if host == noProxy || (strings.HasPrefix(noProxy, ".") && strings.HasSuffix(host, noProxy)) {
				return nil, nil
			}
		}
		
		return proxyURL, nil
	}
}
