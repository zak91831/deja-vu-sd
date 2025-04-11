package execution

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dejavu/scanner/pkg/core/template"
	"github.com/dejavu/scanner/pkg/core/target"
)

// Executor handles the execution of templates against targets
type Executor struct {
	httpClient *http.Client
	rateLimiter *RateLimiter
}

// NewExecutor creates a new executor
func NewExecutor(timeout int, rateLimit int) *Executor {
	return &Executor{
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		},
		rateLimiter: NewRateLimiter(rateLimit),
	}
}

// ExecuteTemplate executes a template against a target
func (e *Executor) ExecuteTemplate(target *target.Target, template *template.Template) (*Result, error) {
	result := &Result{
		Target:   target,
		Template: template,
		Findings: make([]*Finding, 0),
	}

	// Execute each request in the template
	for _, req := range template.Requests {
		// Wait for rate limiter
		e.rateLimiter.Wait()

		// Execute request
		finding, err := e.executeRequest(target, template, &req)
		if err != nil {
			return nil, err
		}

		// Add finding if not nil
		if finding != nil {
			result.Findings = append(result.Findings, finding)
		}
	}

	return result, nil
}

// executeRequest executes a single request from a template
func (e *Executor) executeRequest(target *target.Target, tmpl *template.Template, req *template.Request) (*Finding, error) {
	// Build URL
	url := fmt.Sprintf("%s://%s", target.Protocol, target.Hostname)
	if target.Port != 0 && !((target.Protocol == "http" && target.Port == 80) || (target.Protocol == "https" && target.Port == 443)) {
		url = fmt.Sprintf("%s:%d", url, target.Port)
	}
	url = fmt.Sprintf("%s%s", url, req.Path)

	// Create HTTP request
	httpReq, err := http.NewRequest(req.Method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Set default User-Agent if not specified
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", "Deja Vu Scanner v1.0")
	}

	// Execute request
	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Process response
	finding, err := e.processResponse(target, tmpl, req, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to process response: %w", err)
	}

	return finding, nil
}

// processResponse processes the response from a request
func (e *Executor) processResponse(target *target.Target, tmpl *template.Template, req *template.Request, resp *http.Response) (*Finding, error) {
	// Check if any matchers match
	matched := false
	matcherName := ""

	// This is a simplified implementation
	// In a real implementation, we would read the response body and check all matchers
	for _, matcher := range req.Matchers {
		// For now, just check status code matchers
		if matcher.Type == "status" {
			for _, status := range matcher.Status {
				if resp.StatusCode == status {
					matched = true
					matcherName = fmt.Sprintf("status=%d", status)
					break
				}
			}
		}
	}

	// If no matchers matched, return nil
	if !matched {
		return nil, nil
	}

	// Create finding
	finding := &Finding{
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Info.Name,
		Severity:     tmpl.Info.Severity,
		Target:       target.URL,
		MatcherName:  matcherName,
		Timestamp:    time.Now(),
	}

	return finding, nil
}

// Result represents the result of executing a template against a target
type Result struct {
	Target   *target.Target
	Template *template.Template
	Findings []*Finding
}

// Finding represents a vulnerability finding
type Finding struct {
	TemplateID   string
	TemplateName string
	Severity     string
	Target       string
	MatcherName  string
	Timestamp    time.Time
}

// RateLimiter implements a simple rate limiter
type RateLimiter struct {
	requestsPerSecond int
	lastRequest       time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond int) *RateLimiter {
	return &RateLimiter{
		requestsPerSecond: requestsPerSecond,
		lastRequest:       time.Now().Add(-time.Second), // Allow immediate first request
	}
}

// Wait waits for the rate limiter
func (r *RateLimiter) Wait() {
	if r.requestsPerSecond <= 0 {
		return
	}

	// Calculate time between requests
	interval := time.Second / time.Duration(r.requestsPerSecond)

	// Calculate time to wait
	elapsed := time.Since(r.lastRequest)
	if elapsed < interval {
		time.Sleep(interval - elapsed)
	}

	// Update last request time
	r.lastRequest = time.Now()
}
