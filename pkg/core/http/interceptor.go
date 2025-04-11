package http

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Interceptor defines an interface for intercepting HTTP requests and responses
type Interceptor interface {
	// BeforeRequest is called before a request is sent
	BeforeRequest(req *http.Request) error
	
	// AfterResponse is called after a response is received
	AfterResponse(resp *http.Response, req *http.Request) error
}

// InterceptorChain represents a chain of interceptors
type InterceptorChain struct {
	// interceptors is the list of interceptors in the chain
	interceptors []Interceptor
}

// NewInterceptorChain creates a new interceptor chain
func NewInterceptorChain() *InterceptorChain {
	return &InterceptorChain{
		interceptors: make([]Interceptor, 0),
	}
}

// Add adds an interceptor to the chain
func (c *InterceptorChain) Add(interceptor Interceptor) {
	c.interceptors = append(c.interceptors, interceptor)
}

// BeforeRequest calls all interceptors' BeforeRequest methods
func (c *InterceptorChain) BeforeRequest(req *http.Request) error {
	for _, interceptor := range c.interceptors {
		if err := interceptor.BeforeRequest(req); err != nil {
			return err
		}
	}
	return nil
}

// AfterResponse calls all interceptors' AfterResponse methods
func (c *InterceptorChain) AfterResponse(resp *http.Response, req *http.Request) error {
	for _, interceptor := range c.interceptors {
		if err := interceptor.AfterResponse(resp, req); err != nil {
			return err
		}
	}
	return nil
}

// LoggingInterceptor logs HTTP requests and responses
type LoggingInterceptor struct {
	// Logger is the logger to use
	Logger Logger
}

// Logger defines a simple logging interface
type Logger interface {
	// Debug logs a debug message
	Debug(format string, args ...interface{})
	
	// Info logs an info message
	Info(format string, args ...interface{})
	
	// Error logs an error message
	Error(format string, args ...interface{})
}

// BeforeRequest logs the request
func (i *LoggingInterceptor) BeforeRequest(req *http.Request) error {
	i.Logger.Debug("Sending request: %s %s", req.Method, req.URL.String())
	return nil
}

// AfterResponse logs the response
func (i *LoggingInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	i.Logger.Debug("Received response: %s %s -> %d %s", req.Method, req.URL.String(), resp.StatusCode, resp.Status)
	return nil
}

// HeaderInterceptor adds headers to requests
type HeaderInterceptor struct {
	// Headers are the headers to add
	Headers map[string]string
}

// BeforeRequest adds headers to the request
func (i *HeaderInterceptor) BeforeRequest(req *http.Request) error {
	for key, value := range i.Headers {
		req.Header.Set(key, value)
	}
	return nil
}

// AfterResponse does nothing
func (i *HeaderInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	return nil
}

// RetryInterceptor handles retrying requests
type RetryInterceptor struct {
	// MaxRetries is the maximum number of retries
	MaxRetries int
	
	// RetryStatusCodes are the HTTP status codes that should trigger a retry
	RetryStatusCodes []int
	
	// RetryCount tracks the number of retries for each request
	RetryCount map[*http.Request]int
}

// NewRetryInterceptor creates a new retry interceptor
func NewRetryInterceptor(maxRetries int, retryStatusCodes []int) *RetryInterceptor {
	return &RetryInterceptor{
		MaxRetries:       maxRetries,
		RetryStatusCodes: retryStatusCodes,
		RetryCount:       make(map[*http.Request]int),
	}
}

// BeforeRequest initializes retry count
func (i *RetryInterceptor) BeforeRequest(req *http.Request) error {
	if _, exists := i.RetryCount[req]; !exists {
		i.RetryCount[req] = 0
	}
	return nil
}

// AfterResponse checks if retry is needed
func (i *RetryInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	// Check if status code should trigger retry
	shouldRetry := false
	for _, code := range i.RetryStatusCodes {
		if resp.StatusCode == code {
			shouldRetry = true
			break
		}
	}
	
	if shouldRetry {
		// Check if max retries reached
		if i.RetryCount[req] < i.MaxRetries {
			i.RetryCount[req]++
			return fmt.Errorf("retry needed")
		}
	}
	
	// Clean up retry count
	delete(i.RetryCount, req)
	
	return nil
}

// CookieInterceptor handles cookies
type CookieInterceptor struct {
	// Cookies are the cookies to add
	Cookies []*http.Cookie
}

// BeforeRequest adds cookies to the request
func (i *CookieInterceptor) BeforeRequest(req *http.Request) error {
	for _, cookie := range i.Cookies {
		req.AddCookie(cookie)
	}
	return nil
}

// AfterResponse does nothing
func (i *CookieInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	return nil
}

// UserAgentRotator rotates user agents
type UserAgentRotator struct {
	// UserAgents is the list of user agents to rotate
	UserAgents []string
	
	// CurrentIndex is the index of the current user agent
	CurrentIndex int
}

// NewUserAgentRotator creates a new user agent rotator
func NewUserAgentRotator(userAgents []string) *UserAgentRotator {
	if len(userAgents) == 0 {
		// Default user agents
		userAgents = []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		}
	}
	
	return &UserAgentRotator{
		UserAgents:   userAgents,
		CurrentIndex: 0,
	}
}

// BeforeRequest sets the user agent
func (r *UserAgentRotator) BeforeRequest(req *http.Request) error {
	if len(r.UserAgents) > 0 {
		req.Header.Set("User-Agent", r.UserAgents[r.CurrentIndex])
		r.CurrentIndex = (r.CurrentIndex + 1) % len(r.UserAgents)
	}
	return nil
}

// AfterResponse does nothing
func (r *UserAgentRotator) AfterResponse(resp *http.Response, req *http.Request) error {
	return nil
}

// RedirectInterceptor handles redirects
type RedirectInterceptor struct {
	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int
	
	// FollowRedirects determines whether to follow redirects
	FollowRedirects bool
	
	// RedirectCount tracks the number of redirects for each request
	RedirectCount map[*http.Request]int
}

// NewRedirectInterceptor creates a new redirect interceptor
func NewRedirectInterceptor(maxRedirects int, followRedirects bool) *RedirectInterceptor {
	return &RedirectInterceptor{
		MaxRedirects:    maxRedirects,
		FollowRedirects: followRedirects,
		RedirectCount:   make(map[*http.Request]int),
	}
}

// BeforeRequest initializes redirect count
func (i *RedirectInterceptor) BeforeRequest(req *http.Request) error {
	if _, exists := i.RedirectCount[req]; !exists {
		i.RedirectCount[req] = 0
	}
	return nil
}

// AfterResponse checks if redirect should be followed
func (i *RedirectInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	// Check if response is a redirect
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
		if !i.FollowRedirects {
			return nil
		}
		
		// Check if max redirects reached
		if i.RedirectCount[req] >= i.MaxRedirects {
			delete(i.RedirectCount, req)
			return fmt.Errorf("max redirects reached")
		}
		
		i.RedirectCount[req]++
	} else {
		// Clean up redirect count
		delete(i.RedirectCount, req)
	}
	
	return nil
}

// ContentTypeInterceptor sets content type based on request body
type ContentTypeInterceptor struct{}

// BeforeRequest sets content type
func (i *ContentTypeInterceptor) BeforeRequest(req *http.Request) error {
	// Only set content type if not already set
	if req.Header.Get("Content-Type") == "" && req.Body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return nil
}

// AfterResponse does nothing
func (i *ContentTypeInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	return nil
}

// RequestFilterInterceptor filters requests based on patterns
type RequestFilterInterceptor struct {
	// AllowPatterns are the URL patterns to allow
	AllowPatterns []*regexp.Regexp
	
	// BlockPatterns are the URL patterns to block
	BlockPatterns []*regexp.Regexp
}

// NewRequestFilterInterceptor creates a new request filter interceptor
func NewRequestFilterInterceptor() *RequestFilterInterceptor {
	return &RequestFilterInterceptor{
		AllowPatterns: make([]*regexp.Regexp, 0),
		BlockPatterns: make([]*regexp.Regexp, 0),
	}
}

// AddAllowPattern adds an allow pattern
func (i *RequestFilterInterceptor) AddAllowPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	
	i.AllowPatterns = append(i.AllowPatterns, re)
	return nil
}

// AddBlockPattern adds a block pattern
func (i *RequestFilterInterceptor) AddBlockPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	
	i.BlockPatterns = append(i.BlockPatterns, re)
	return nil
}

// BeforeRequest checks if request should be allowed
func (i *RequestFilterInterceptor) BeforeRequest(req *http.Request) error {
	url := req.URL.String()
	
	// Check block patterns first
	for _, pattern := range i.BlockPatterns {
		if pattern.MatchString(url) {
			return fmt.Errorf("request blocked by pattern: %s", pattern.String())
		}
	}
	
	// If allow patterns are specified, at least one must match
	if len(i.AllowPatterns) > 0 {
		allowed := false
		for _, pattern := range i.AllowPatterns {
			if pattern.MatchString(url) {
				allowed = true
				break
			}
		}
		
		if !allowed {
			return fmt.Errorf("request not allowed by any pattern")
		}
	}
	
	return nil
}

// AfterResponse does nothing
func (i *RequestFilterInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	return nil
}

// ResponseValidatorInterceptor validates responses
type ResponseValidatorInterceptor struct {
	// ValidStatusCodes are the valid status codes
	ValidStatusCodes []int
	
	// RequiredHeaders are the headers that must be present
	RequiredHeaders []string
	
	// RequiredBodyPatterns are the patterns that must be present in the body
	RequiredBodyPatterns []*regexp.Regexp
}

// NewResponseValidatorInterceptor creates a new response validator interceptor
func NewResponseValidatorInterceptor() *ResponseValidatorInterceptor {
	return &ResponseValidatorInterceptor{
		ValidStatusCodes:    make([]int, 0),
		RequiredHeaders:     make([]string, 0),
		RequiredBodyPatterns: make([]*regexp.Regexp, 0),
	}
}

// AddValidStatusCode adds a valid status code
func (i *ResponseValidatorInterceptor) AddValidStatusCode(code int) {
	i.ValidStatusCodes = append(i.ValidStatusCodes, code)
}

// AddRequiredHeader adds a required header
func (i *ResponseValidatorInterceptor) AddRequiredHeader(header string) {
	i.RequiredHeaders = append(i.RequiredHeaders, header)
}

// AddRequiredBodyPattern adds a required body pattern
func (i *ResponseValidatorInterceptor) AddRequiredBodyPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	
	i.RequiredBodyPatterns = append(i.RequiredBodyPatterns, re)
	return nil
}

// BeforeRequest does nothing
func (i *ResponseValidatorInterceptor) BeforeRequest(req *http.Request) error {
	return nil
}

// AfterResponse validates the response
func (i *ResponseValidatorInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	// Check status code
	if len(i.ValidStatusCodes) > 0 {
		valid := false
		for _, code := range i.ValidStatusCodes {
			if resp.StatusCode == code {
				valid = true
				break
			}
		}
		
		if !valid {
			return fmt.Errorf("invalid status code: %d", resp.StatusCode)
		}
	}
	
	// Check required headers
	for _, header := range i.RequiredHeaders {
		if resp.Header.Get(header) == "" {
			return fmt.Errorf("missing required header: %s", header)
		}
	}
	
	// Check required body patterns
	// This would normally read the body, but that would consume it
	// In a real implementation, this would need to copy the body
	
	return nil
}

// CompressionInterceptor handles compression
type CompressionInterceptor struct {
	// AcceptEncoding is the Accept-Encoding header value
	AcceptEncoding string
}

// NewCompressionInterceptor creates a new compression interceptor
func NewCompressionInterceptor(acceptEncoding string) *CompressionInterceptor {
	if acceptEncoding == "" {
		acceptEncoding = "gzip, deflate"
	}
	
	return &CompressionInterceptor{
		AcceptEncoding: acceptEncoding,
	}
}

// BeforeRequest sets the Accept-Encoding header
func (i *CompressionInterceptor) BeforeRequest(req *http.Request) error {
	req.Header.Set("Accept-Encoding", i.AcceptEncoding)
	return nil
}

// AfterResponse does nothing
func (i *CompressionInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	// In a real implementation, this would handle decompression
	return nil
}

// CustomInterceptor allows custom interception logic
type CustomInterceptor struct {
	// BeforeRequestFunc is the function to call before a request
	BeforeRequestFunc func(*http.Request) error
	
	// AfterResponseFunc is the function to call after a response
	AfterResponseFunc func(*http.Response, *http.Request) error
}

// BeforeRequest calls the before request function
func (i *CustomInterceptor) BeforeRequest(req *http.Request) error {
	if i.BeforeRequestFunc != nil {
		return i.BeforeRequestFunc(req)
	}
	return nil
}

// AfterResponse calls the after response function
func (i *CustomInterceptor) AfterResponse(resp *http.Response, req *http.Request) error {
	if i.AfterResponseFunc != nil {
		return i.AfterResponseFunc(resp, req)
	}
	return nil
}
