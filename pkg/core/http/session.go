package http

import (
	"net/http"
	"sync"
)

// Session represents a persistent session for HTTP requests
type Session struct {
	// ID is the unique identifier for the session
	ID string
	
	// Cookies are the cookies associated with the session
	Cookies []*http.Cookie
	
	// Headers are the headers to be sent with each request in this session
	Headers map[string]string
	
	// State contains arbitrary session state data
	State map[string]interface{}
	
	// mutex protects concurrent access to session data
	mutex sync.RWMutex
}

// NewSession creates a new session with the given ID
func NewSession(id string) *Session {
	return &Session{
		ID:      id,
		Cookies: make([]*http.Cookie, 0),
		Headers: make(map[string]string),
		State:   make(map[string]interface{}),
	}
}

// AddCookie adds a cookie to the session
func (s *Session) AddCookie(cookie *http.Cookie) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Replace existing cookie with same name if it exists
	for i, c := range s.Cookies {
		if c.Name == cookie.Name {
			s.Cookies[i] = cookie
			return
		}
	}
	
	// Add new cookie
	s.Cookies = append(s.Cookies, cookie)
}

// GetCookie gets a cookie by name
func (s *Session) GetCookie(name string) (*http.Cookie, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	for _, cookie := range s.Cookies {
		if cookie.Name == name {
			return cookie, true
		}
	}
	
	return nil, false
}

// RemoveCookie removes a cookie by name
func (s *Session) RemoveCookie(name string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	for i, cookie := range s.Cookies {
		if cookie.Name == name {
			s.Cookies = append(s.Cookies[:i], s.Cookies[i+1:]...)
			return
		}
	}
}

// SetHeader sets a header for the session
func (s *Session) SetHeader(key, value string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.Headers[key] = value
}

// GetHeader gets a header by key
func (s *Session) GetHeader(key string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	value, exists := s.Headers[key]
	return value, exists
}

// RemoveHeader removes a header by key
func (s *Session) RemoveHeader(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	delete(s.Headers, key)
}

// SetState sets a state value
func (s *Session) SetState(key string, value interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.State[key] = value
}

// GetState gets a state value by key
func (s *Session) GetState(key string) (interface{}, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	value, exists := s.State[key]
	return value, exists
}

// RemoveState removes a state value by key
func (s *Session) RemoveState(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	delete(s.State, key)
}

// ApplyToRequest applies the session to an HTTP request
func (s *Session) ApplyToRequest(req *http.Request) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	// Apply headers
	for key, value := range s.Headers {
		req.Header.Set(key, value)
	}
	
	// Apply cookies
	for _, cookie := range s.Cookies {
		req.AddCookie(cookie)
	}
}

// UpdateFromResponse updates the session from an HTTP response
func (s *Session) UpdateFromResponse(resp *http.Response) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Update cookies from response
	for _, cookie := range resp.Cookies() {
		// Replace existing cookie with same name if it exists
		found := false
		for i, c := range s.Cookies {
			if c.Name == cookie.Name {
				s.Cookies[i] = cookie
				found = true
				break
			}
		}
		
		// Add new cookie if not found
		if !found {
			s.Cookies = append(s.Cookies, cookie)
		}
	}
}

// Clear clears all session data
func (s *Session) Clear() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.Cookies = make([]*http.Cookie, 0)
	s.Headers = make(map[string]string)
	s.State = make(map[string]interface{})
}
