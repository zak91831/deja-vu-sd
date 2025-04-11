package http

import (
	"context"
	"sync"
	"time"
)

// RateLimiterType defines the type of rate limiter
type RateLimiterType string

const (
	// FixedRateLimiter uses a fixed rate limit
	FixedRateLimiter RateLimiterType = "fixed"
	
	// AdaptiveRateLimiter adjusts rate limits based on responses
	AdaptiveRateLimiter RateLimiterType = "adaptive"
)

// FixedRateLimiter implements a simple fixed rate limiter
type fixedRateLimiter struct {
	// requestsPerSecond is the maximum number of requests per second
	requestsPerSecond int
	
	// lastRequest is the time of the last request
	lastRequest time.Time
	
	// mutex protects concurrent access
	mutex sync.Mutex
}

// NewFixedRateLimiter creates a new fixed rate limiter
func NewFixedRateLimiter(requestsPerSecond int) RateLimiter {
	return &fixedRateLimiter{
		requestsPerSecond: requestsPerSecond,
		lastRequest:       time.Now().Add(-time.Second), // Allow immediate first request
	}
}

// Wait blocks until a request can be made
func (r *fixedRateLimiter) Wait(ctx context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	// Calculate time since last request
	now := time.Now()
	elapsed := now.Sub(r.lastRequest)
	
	// Calculate minimum time between requests
	minInterval := time.Second / time.Duration(r.requestsPerSecond)
	
	// If not enough time has passed, wait
	if elapsed < minInterval {
		waitTime := minInterval - elapsed
		
		// Use context with timeout
		timer := time.NewTimer(waitTime)
		defer timer.Stop()
		
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			// Continue after waiting
		}
	}
	
	// Update last request time
	r.lastRequest = time.Now()
	
	return nil
}

// UpdateRate updates the rate limit based on response (no-op for fixed rate limiter)
func (r *fixedRateLimiter) UpdateRate(resp *http.Response) {
	// Fixed rate limiter doesn't adjust based on responses
}

// adaptiveRateLimiter implements an adaptive rate limiter that adjusts based on responses
type adaptiveRateLimiter struct {
	// minRequestsPerSecond is the minimum requests per second
	minRequestsPerSecond int
	
	// maxRequestsPerSecond is the maximum requests per second
	maxRequestsPerSecond int
	
	// currentRequestsPerSecond is the current requests per second
	currentRequestsPerSecond int
	
	// lastRequest is the time of the last request
	lastRequest time.Time
	
	// consecutiveErrors is the number of consecutive error responses
	consecutiveErrors int
	
	// consecutiveSuccesses is the number of consecutive successful responses
	consecutiveSuccesses int
	
	// mutex protects concurrent access
	mutex sync.Mutex
}

// NewAdaptiveRateLimiter creates a new adaptive rate limiter
func NewAdaptiveRateLimiter(minRequestsPerSecond, maxRequestsPerSecond int) RateLimiter {
	// Ensure min <= max
	if minRequestsPerSecond > maxRequestsPerSecond {
		minRequestsPerSecond = maxRequestsPerSecond
	}
	
	// Start at the middle of the range
	initialRate := (minRequestsPerSecond + maxRequestsPerSecond) / 2
	
	return &adaptiveRateLimiter{
		minRequestsPerSecond:     minRequestsPerSecond,
		maxRequestsPerSecond:     maxRequestsPerSecond,
		currentRequestsPerSecond: initialRate,
		lastRequest:              time.Now().Add(-time.Second), // Allow immediate first request
		consecutiveErrors:        0,
		consecutiveSuccesses:     0,
	}
}

// Wait blocks until a request can be made
func (r *adaptiveRateLimiter) Wait(ctx context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	// Calculate time since last request
	now := time.Now()
	elapsed := now.Sub(r.lastRequest)
	
	// Calculate minimum time between requests based on current rate
	minInterval := time.Second / time.Duration(r.currentRequestsPerSecond)
	
	// If not enough time has passed, wait
	if elapsed < minInterval {
		waitTime := minInterval - elapsed
		
		// Use context with timeout
		timer := time.NewTimer(waitTime)
		defer timer.Stop()
		
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			// Continue after waiting
		}
	}
	
	// Update last request time
	r.lastRequest = time.Now()
	
	return nil
}

// UpdateRate updates the rate limit based on response
func (r *adaptiveRateLimiter) UpdateRate(resp *http.Response) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	// Check for rate limiting response codes
	if resp.StatusCode == 429 || resp.StatusCode == 503 {
		// Rate limited, decrease rate
		r.consecutiveErrors++
		r.consecutiveSuccesses = 0
		
		// Exponential backoff based on consecutive errors
		decreaseFactor := 1 + (r.consecutiveErrors * 0.5)
		newRate := int(float64(r.currentRequestsPerSecond) / decreaseFactor)
		
		// Ensure we don't go below minimum
		if newRate < r.minRequestsPerSecond {
			newRate = r.minRequestsPerSecond
		}
		
		r.currentRequestsPerSecond = newRate
		return
	}
	
	// Check for server errors
	if resp.StatusCode >= 500 && resp.StatusCode != 503 {
		// Server error, slight decrease in rate
		r.consecutiveErrors++
		r.consecutiveSuccesses = 0
		
		// Linear backoff for server errors
		newRate := r.currentRequestsPerSecond - 1
		
		// Ensure we don't go below minimum
		if newRate < r.minRequestsPerSecond {
			newRate = r.minRequestsPerSecond
		}
		
		r.currentRequestsPerSecond = newRate
		return
	}
	
	// Successful response
	r.consecutiveErrors = 0
	r.consecutiveSuccesses++
	
	// Only increase rate after several consecutive successes
	if r.consecutiveSuccesses >= 5 {
		// Gradual increase in rate
		increaseFactor := 1.1
		newRate := int(float64(r.currentRequestsPerSecond) * increaseFactor)
		
		// Ensure we don't exceed maximum
		if newRate > r.maxRequestsPerSecond {
			newRate = r.maxRequestsPerSecond
		}
		
		r.currentRequestsPerSecond = newRate
		r.consecutiveSuccesses = 0 // Reset counter after adjustment
	}
}

// TokenBucketRateLimiter implements a token bucket rate limiter
type tokenBucketRateLimiter struct {
	// tokensPerSecond is the rate at which tokens are added to the bucket
	tokensPerSecond float64
	
	// maxTokens is the maximum number of tokens the bucket can hold
	maxTokens float64
	
	// availableTokens is the current number of tokens in the bucket
	availableTokens float64
	
	// lastRefill is the time of the last token refill
	lastRefill time.Time
	
	// mutex protects concurrent access
	mutex sync.Mutex
}

// NewTokenBucketRateLimiter creates a new token bucket rate limiter
func NewTokenBucketRateLimiter(tokensPerSecond, burstSize float64) RateLimiter {
	return &tokenBucketRateLimiter{
		tokensPerSecond: tokensPerSecond,
		maxTokens:       burstSize,
		availableTokens: burstSize, // Start with a full bucket
		lastRefill:      time.Now(),
	}
}

// Wait blocks until a token is available
func (r *tokenBucketRateLimiter) Wait(ctx context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.lastRefill = now
	
	// Calculate tokens to add
	newTokens := elapsed * r.tokensPerSecond
	r.availableTokens += newTokens
	if r.availableTokens > r.maxTokens {
		r.availableTokens = r.maxTokens
	}
	
	// If we have at least one token, use it immediately
	if r.availableTokens >= 1 {
		r.availableTokens--
		return nil
	}
	
	// Calculate wait time until next token
	waitTime := time.Duration((1 - r.availableTokens) * float64(time.Second) / r.tokensPerSecond)
	
	// Use context with timeout
	timer := time.NewTimer(waitTime)
	defer timer.Stop()
	
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		// Token should be available now
		r.availableTokens--
		return nil
	}
}

// UpdateRate updates the rate limit based on response
func (r *tokenBucketRateLimiter) UpdateRate(resp *http.Response) {
	// Token bucket doesn't adjust based on responses by default
	// Could be extended to implement adaptive token bucket
}
