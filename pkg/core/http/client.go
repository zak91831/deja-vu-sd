package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// ClientOptions contains configuration options for the HTTP client
type ClientOptions struct {
	// Timeout for HTTP requests
	Timeout time.Duration
	
	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int
	
	// FollowRedirects determines whether to follow redirects
	FollowRedirects bool
	
	// Proxy URL to use for requests
	Proxy string
	
	// TLSConfig for customizing TLS behavior
	TLSConfig *tls.Config
	
	// EnableCookies determines whether to store and send cookies
	EnableCookies bool
	
	// UserAgent to use in HTTP requests
	UserAgent string
	
	// RetryConfig for configuring retry behavior
	RetryConfig *RetryConfig
	
	// RateLimiter for controlling request rates
	RateLimiter RateLimiter
}

// RetryConfig contains configuration for retry behavior
type RetryConfig struct {
	// MaxRetries is the maximum number of retries
	MaxRetries int
	
	// RetryDelay is the delay between retries
	RetryDelay time.Duration
	
	// RetryJitter is the maximum random jitter to add to retry delay
	RetryJitter time.Duration
	
	// RetryStatusCodes are the HTTP status codes that should trigger a retry
	RetryStatusCodes []int
}

// RateLimiter defines the interface for rate limiting HTTP requests
type RateLimiter interface {
	// Wait blocks until a request can be made
	Wait(ctx context.Context) error
	
	// UpdateRate updates the rate limit based on response
	UpdateRate(resp *http.Response)
}

// DefaultClientOptions returns the default options for the HTTP client
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		Timeout:         30 * time.Second,
		MaxRedirects:    10,
		FollowRedirects: true,
		EnableCookies:   true,
		UserAgent:       "Deja-Vu-Scanner/2.0",
		RetryConfig: &RetryConfig{
			MaxRetries:       3,
			RetryDelay:       1 * time.Second,
			RetryJitter:      500 * time.Millisecond,
			RetryStatusCodes: []int{408, 429, 500, 502, 503, 504},
		},
		RateLimiter: NewAdaptiveRateLimiter(10, 100),
	}
}

// Client is an enhanced HTTP client for vulnerability scanning
type Client struct {
	client      *http.Client
	options     *ClientOptions
	cookieJar   *cookiejar.Jar
	rateLimiter RateLimiter
	mutex       sync.RWMutex
	sessions    map[string]*Session
}

// NewClient creates a new HTTP client with the given options
func NewClient(options *ClientOptions) (*Client, error) {
	if options == nil {
		options = DefaultClientOptions()
	}

	var jar *cookiejar.Jar
	var err error
	
	if options.EnableCookies {
		jar, err = cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create cookie jar: %w", err)
		}
	}

	transport := &http.Transport{
		TLSClientConfig:       options.TLSConfig,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}

	if options.Proxy != "" {
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		Jar:       jar,
	}

	// Configure redirect handling
	if !options.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if options.MaxRedirects > 0 {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= options.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", options.MaxRedirects)
			}
			return nil
		}
	}

	rateLimiter := options.RateLimiter
	if rateLimiter == nil {
		rateLimiter = NewAdaptiveRateLimiter(10, 100)
	}

	return &Client{
		client:      client,
		options:     options,
		cookieJar:   jar,
		rateLimiter: rateLimiter,
		sessions:    make(map[string]*Session),
	}, nil
}

// Request represents an HTTP request to be sent
type Request struct {
	// Method is the HTTP method (GET, POST, etc.)
	Method string
	
	// URL is the target URL
	URL string
	
	// Headers are the HTTP headers to send
	Headers map[string]string
	
	// Cookies are the cookies to send with the request
	Cookies []*http.Cookie
	
	// Body is the request body
	Body io.Reader
	
	// BodyBytes is the request body as bytes (alternative to Body)
	BodyBytes []byte
	
	// BodyString is the request body as string (alternative to Body)
	BodyString string
	
	// BodyJSON is the request body as an object to be JSON encoded
	BodyJSON interface{}
	
	// BodyForm is the request body as form values
	BodyForm url.Values
	
	// Context for the request
	Context context.Context
	
	// Timeout for this specific request, overrides client timeout
	Timeout time.Duration
	
	// SessionID to use for this request
	SessionID string
}

// Response represents an HTTP response
type Response struct {
	// StatusCode is the HTTP status code
	StatusCode int
	
	// Status is the HTTP status text
	Status string
	
	// Headers are the HTTP response headers
	Headers http.Header
	
	// Cookies are the cookies received with the response
	Cookies []*http.Cookie
	
	// Body is the response body
	Body []byte
	
	// Request is the original request
	Request *http.Request
	
	// RawResponse is the underlying http.Response
	RawResponse *http.Response
	
	// Duration is how long the request took
	Duration time.Duration
	
	// Redirects contains the chain of redirects
	Redirects []*Response
}

// Do sends an HTTP request and returns the response
func (c *Client) Do(req *Request) (*Response, error) {
	if req.Context == nil {
		req.Context = context.Background()
	}

	// Apply timeout if specified
	var ctx context.Context
	var cancel context.CancelFunc
	if req.Timeout > 0 {
		ctx, cancel = context.WithTimeout(req.Context, req.Timeout)
	} else {
		ctx, cancel = context.WithTimeout(req.Context, c.options.Timeout)
	}
	defer cancel()

	// Prepare the request body
	var body io.Reader
	if req.Body != nil {
		body = req.Body
	} else if len(req.BodyBytes) > 0 {
		body = bytes.NewReader(req.BodyBytes)
	} else if req.BodyString != "" {
		body = strings.NewReader(req.BodyString)
	} else if req.BodyJSON != nil {
		jsonData, err := json.Marshal(req.BodyJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON body: %w", err)
		}
		body = bytes.NewReader(jsonData)
	} else if req.BodyForm != nil {
		body = strings.NewReader(req.BodyForm.Encode())
	}

	// Create the HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", c.options.UserAgent)
	}

	// Set request headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Set content type based on body type if not already set
	if httpReq.Header.Get("Content-Type") == "" {
		if req.BodyJSON != nil {
			httpReq.Header.Set("Content-Type", "application/json")
		} else if req.BodyForm != nil {
			httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	// Add cookies
	for _, cookie := range req.Cookies {
		httpReq.AddCookie(cookie)
	}

	// Use session if specified
	if req.SessionID != "" {
		c.mutex.RLock()
		session, exists := c.sessions[req.SessionID]
		c.mutex.RUnlock()

		if exists {
			session.ApplyToRequest(httpReq)
		}
	}

	// Apply rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiting error: %w", err)
		}
	}

	// Send the request with retries if configured
	var httpResp *http.Response
	var respErr error
	startTime := time.Now()

	if c.options.RetryConfig != nil && c.options.RetryConfig.MaxRetries > 0 {
		httpResp, respErr = c.doWithRetries(httpReq, c.options.RetryConfig)
	} else {
		httpResp, respErr = c.client.Do(httpReq)
	}

	duration := time.Since(startTime)

	if respErr != nil {
		return nil, fmt.Errorf("request failed: %w", respErr)
	}
	defer httpResp.Body.Close()

	// Update rate limiter based on response
	if c.rateLimiter != nil {
		c.rateLimiter.UpdateRate(httpResp)
	}

	// Read response body
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Create response object
	resp := &Response{
		StatusCode:  httpResp.StatusCode,
		Status:      httpResp.Status,
		Headers:     httpResp.Header,
		Cookies:     httpResp.Cookies(),
		Body:        respBody,
		Request:     httpReq,
		RawResponse: httpResp,
		Duration:    duration,
	}

	// Update session if specified
	if req.SessionID != "" {
		c.mutex.RLock()
		session, exists := c.sessions[req.SessionID]
		c.mutex.RUnlock()

		if exists {
			session.UpdateFromResponse(httpResp)
		}
	}

	return resp, nil
}

// doWithRetries sends an HTTP request with retries
func (c *Client) doWithRetries(req *http.Request, retryConfig *RetryConfig) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= retryConfig.MaxRetries; attempt++ {
		// Clone the request to ensure it can be sent multiple times
		reqClone := req.Clone(req.Context)
		if req.Body != nil {
			// We need to recreate the body for each attempt
			if bodySeeker, ok := req.Body.(io.ReadSeeker); ok {
				_, _ = bodySeeker.Seek(0, io.SeekStart)
				reqClone.Body = req.Body
			}
		}

		resp, err = c.client.Do(reqClone)
		
		// If successful or not a retryable error, return
		if err == nil && !isRetryableStatus(resp.StatusCode, retryConfig.RetryStatusCodes) {
			return resp, nil
		}

		// If this was the last attempt, return the error
		if attempt == retryConfig.MaxRetries {
			if err != nil {
				return nil, err
			}
			return resp, nil
		}

		// Close the response body if we got a response
		if resp != nil {
			resp.Body.Close()
		}

		// Calculate retry delay with jitter
		delay := retryConfig.RetryDelay
		if retryConfig.RetryJitter > 0 {
			jitter := time.Duration(float64(retryConfig.RetryJitter) * (float64(attempt+1) / float64(retryConfig.MaxRetries)))
			delay += time.Duration(float64(jitter) * (0.5 + float64(time.Now().UnixNano()%1000)/1000.0))
		}

		// Wait before retrying
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	// This should never happen due to the return in the loop
	return resp, err
}

// isRetryableStatus checks if a status code should trigger a retry
func isRetryableStatus(statusCode int, retryStatusCodes []int) bool {
	for _, code := range retryStatusCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// Get sends a GET request
func (c *Client) Get(url string, headers map[string]string) (*Response, error) {
	return c.Do(&Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post sends a POST request
func (c *Client) Post(url string, headers map[string]string, body interface{}) (*Response, error) {
	req := &Request{
		Method:  "POST",
		URL:     url,
		Headers: headers,
	}

	switch v := body.(type) {
	case string:
		req.BodyString = v
	case []byte:
		req.BodyBytes = v
	case io.Reader:
		req.Body = v
	case url.Values:
		req.BodyForm = v
	default:
		req.BodyJSON = v
	}

	return c.Do(req)
}

// CreateSession creates a new session with the given ID
func (c *Client) CreateSession(id string) *Session {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	session := NewSession(id)
	c.sessions[id] = session
	return session
}

// GetSession returns the session with the given ID
func (c *Client) GetSession(id string) (*Session, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	session, exists := c.sessions[id]
	return session, exists
}

// DeleteSession deletes the session with the given ID
func (c *Client) DeleteSession(id string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.sessions, id)
}

// SetCookies sets cookies for the given URL
func (c *Client) SetCookies(urlStr string, cookies []*http.Cookie) error {
	if !c.options.EnableCookies || c.cookieJar == nil {
		return fmt.Errorf("cookies are disabled")
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	c.cookieJar.SetCookies(parsedURL, cookies)
	return nil
}

// GetCookies returns cookies for the given URL
func (c *Client) GetCookies(urlStr string) ([]*http.Cookie, error) {
	if !c.options.EnableCookies || c.cookieJar == nil {
		return nil, fmt.Errorf("cookies are disabled")
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	return c.cookieJar.Cookies(parsedURL), nil
}

// SetRateLimiter sets the rate limiter for the client
func (c *Client) SetRateLimiter(limiter RateLimiter) {
	c.rateLimiter = limiter
}

// Close closes the client and releases resources
func (c *Client) Close() error {
	c.client.CloseIdleConnections()
	return nil
}
