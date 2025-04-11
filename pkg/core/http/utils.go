package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ResponseProcessor processes HTTP responses
type ResponseProcessor struct {
	// Decompressors is a map of content encoding to decompressor
	Decompressors map[string]Decompressor
}

// Decompressor decompresses data
type Decompressor interface {
	// Decompress decompresses data
	Decompress(data []byte) ([]byte, error)
}

// NewResponseProcessor creates a new response processor
func NewResponseProcessor() *ResponseProcessor {
	return &ResponseProcessor{
		Decompressors: map[string]Decompressor{
			"gzip":    &GzipDecompressor{},
			"deflate": &DeflateDecompressor{},
		},
	}
}

// Process processes a response
func (p *ResponseProcessor) Process(resp *http.Response) (*Response, error) {
	if resp == nil {
		return nil, fmt.Errorf("response is nil")
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle compression
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		// Try to decompress
		decompressor, exists := p.Decompressors[strings.ToLower(contentEncoding)]
		if exists {
			decompressedBody, err := decompressor.Decompress(body)
			if err != nil {
				return nil, fmt.Errorf("failed to decompress response body: %w", err)
			}
			body = decompressedBody
		}
	}

	// Create response object
	response := &Response{
		StatusCode:  resp.StatusCode,
		Status:      resp.Status,
		Headers:     resp.Header,
		Cookies:     resp.Cookies(),
		Body:        body,
		Request:     resp.Request,
		RawResponse: resp,
	}

	return response, nil
}

// GzipDecompressor decompresses gzip data
type GzipDecompressor struct{}

// Decompress decompresses gzip data
func (d *GzipDecompressor) Decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

// DeflateDecompressor decompresses deflate data
type DeflateDecompressor struct{}

// Decompress decompresses deflate data
func (d *DeflateDecompressor) Decompress(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

// HTTPClientFactory creates HTTP clients
type HTTPClientFactory struct {
	// DefaultOptions are the default options for new clients
	DefaultOptions *ClientOptions
}

// NewHTTPClientFactory creates a new HTTP client factory
func NewHTTPClientFactory() *HTTPClientFactory {
	return &HTTPClientFactory{
		DefaultOptions: DefaultClientOptions(),
	}
}

// CreateClient creates a new HTTP client with the given options
func (f *HTTPClientFactory) CreateClient(options *ClientOptions) (*Client, error) {
	if options == nil {
		options = f.DefaultOptions
	}

	return NewClient(options)
}

// CreateDefaultClient creates a new HTTP client with default options
func (f *HTTPClientFactory) CreateDefaultClient() (*Client, error) {
	return f.CreateClient(nil)
}

// CreateSecureClient creates a new HTTP client with secure options
func (f *HTTPClientFactory) CreateSecureClient() (*Client, error) {
	options := DefaultClientOptions()
	options.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	options.FollowRedirects = true
	options.MaxRedirects = 5
	options.EnableCookies = true

	return f.CreateClient(options)
}

// CreateAnonymousClient creates a new HTTP client with anonymous options
func (f *HTTPClientFactory) CreateAnonymousClient() (*Client, error) {
	options := DefaultClientOptions()
	options.EnableCookies = false
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

	return f.CreateClient(options)
}

// CreateHighPerformanceClient creates a new HTTP client optimized for performance
func (f *HTTPClientFactory) CreateHighPerformanceClient() (*Client, error) {
	options := DefaultClientOptions()
	options.Timeout = 10 * time.Second
	options.RetryConfig = nil // No retries for performance
	options.RateLimiter = nil // No rate limiting for performance

	return f.CreateClient(options)
}

// CreatePersonaClient creates a new HTTP client with a specific persona
func (f *HTTPClientFactory) CreatePersonaClient(persona string) (*Client, error) {
	options := DefaultClientOptions()

	switch strings.ToLower(persona) {
	case "standard":
		// Default options are fine
	case "stealthy":
		options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
		options.RateLimiter = NewAdaptiveRateLimiter(1, 5) // Very slow
		options.RetryConfig.MaxRetries = 1                 // Minimal retries
	case "aggressive":
		options.UserAgent = "Deja-Vu-Scanner/2.0 (Aggressive Mode)"
		options.RateLimiter = NewAdaptiveRateLimiter(20, 100) // Fast
		options.RetryConfig.MaxRetries = 5                    // More retries
	case "apt":
		options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
		options.RateLimiter = NewAdaptiveRateLimiter(2, 10) // Slow but not too slow
		options.RetryConfig.MaxRetries = 3                  // Moderate retries
	default:
		return nil, fmt.Errorf("unknown persona: %s", persona)
	}

	return f.CreateClient(options)
}

// HTTPUtils provides utility functions for HTTP
type HTTPUtils struct{}

// ParseURL parses a URL and ensures it's valid
func (u *HTTPUtils) ParseURL(urlStr string) (*url.URL, error) {
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}

	return url.Parse(urlStr)
}

// JoinURL joins a base URL and a path
func (u *HTTPUtils) JoinURL(baseURL, path string) (string, error) {
	base, err := u.ParseURL(baseURL)
	if err != nil {
		return "", err
	}

	// Handle absolute paths
	if strings.HasPrefix(path, "/") {
		base.Path = path
		return base.String(), nil
	}

	// Handle relative paths
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	base.Path += path

	return base.String(), nil
}

// IsAbsoluteURL checks if a URL is absolute
func (u *HTTPUtils) IsAbsoluteURL(urlStr string) bool {
	return strings.Contains(urlStr, "://")
}

// NormalizeURL normalizes a URL
func (u *HTTPUtils) NormalizeURL(urlStr string) (string, error) {
	parsedURL, err := u.ParseURL(urlStr)
	if err != nil {
		return "", err
	}

	// Remove default ports
	if (parsedURL.Scheme == "http" && parsedURL.Port() == "80") ||
		(parsedURL.Scheme == "https" && parsedURL.Port() == "443") {
		parsedURL.Host = parsedURL.Hostname()
	}

	// Ensure path has trailing slash if empty
	if parsedURL.Path == "" {
		parsedURL.Path = "/"
	}

	// Remove fragment
	parsedURL.Fragment = ""

	return parsedURL.String(), nil
}

// ExtractHostname extracts the hostname from a URL
func (u *HTTPUtils) ExtractHostname(urlStr string) (string, error) {
	parsedURL, err := u.ParseURL(urlStr)
	if err != nil {
		return "", err
	}

	return parsedURL.Hostname(), nil
}

// ExtractDomain extracts the domain from a URL
func (u *HTTPUtils) ExtractDomain(urlStr string) (string, error) {
	hostname, err := u.ExtractHostname(urlStr)
	if err != nil {
		return "", err
	}

	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname, nil
	}

	return strings.Join(parts[len(parts)-2:], "."), nil
}

// GetContentType gets the content type from a response
func (u *HTTPUtils) GetContentType(resp *http.Response) string {
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		return "application/octet-stream"
	}

	// Extract media type
	mediaType := strings.Split(contentType, ";")[0]
	return strings.TrimSpace(mediaType)
}

// IsTextContent checks if content is text
func (u *HTTPUtils) IsTextContent(contentType string) bool {
	return strings.HasPrefix(contentType, "text/") ||
		contentType == "application/json" ||
		contentType == "application/xml" ||
		contentType == "application/javascript"
}

// IsBinaryContent checks if content is binary
func (u *HTTPUtils) IsBinaryContent(contentType string) bool {
	return !u.IsTextContent(contentType)
}

// IsImageContent checks if content is an image
func (u *HTTPUtils) IsImageContent(contentType string) bool {
	return strings.HasPrefix(contentType, "image/")
}

// IsHTMLContent checks if content is HTML
func (u *HTTPUtils) IsHTMLContent(contentType string) bool {
	return contentType == "text/html" || contentType == "application/xhtml+xml"
}
