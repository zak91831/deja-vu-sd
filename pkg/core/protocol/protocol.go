package protocol

import (
	"fmt"
	"net/http"
)

// Protocol defines the interface for all protocol handlers
type Protocol interface {
	// Name returns the protocol name
	Name() string
	
	// Scheme returns the protocol scheme (e.g., http, https, ws)
	Scheme() string
	
	// DefaultPort returns the default port for the protocol
	DefaultPort() int
	
	// Execute executes a request using this protocol
	Execute(req *Request) (*Response, error)
	
	// CanHandle checks if this protocol can handle the given request
	CanHandle(req *Request) bool
}

// Request represents a protocol-agnostic request
type Request struct {
	// URL is the target URL
	URL string
	
	// Method is the request method
	Method string
	
	// Headers are the request headers
	Headers map[string][]string
	
	// Body is the request body
	Body []byte
	
	// Params are additional parameters for the request
	Params map[string]interface{}
	
	// Timeout is the request timeout in seconds
	Timeout int
	
	// FollowRedirects determines whether to follow redirects
	FollowRedirects bool
	
	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int
}

// Response represents a protocol-agnostic response
type Response struct {
	// StatusCode is the response status code
	StatusCode int
	
	// Headers are the response headers
	Headers map[string][]string
	
	// Body is the response body
	Body []byte
	
	// Protocol is the protocol used for the response
	Protocol string
	
	// Raw contains protocol-specific raw response data
	Raw interface{}
	
	// Request is the original request
	Request *Request
	
	// Error is any error that occurred during the request
	Error error
}

// ProtocolRegistry manages protocol handlers
type ProtocolRegistry struct {
	// protocols is a map of protocol name to handler
	protocols map[string]Protocol
	
	// schemeHandlers is a map of scheme to handler
	schemeHandlers map[string]Protocol
}

// NewProtocolRegistry creates a new protocol registry
func NewProtocolRegistry() *ProtocolRegistry {
	return &ProtocolRegistry{
		protocols:      make(map[string]Protocol),
		schemeHandlers: make(map[string]Protocol),
	}
}

// Register registers a protocol handler
func (r *ProtocolRegistry) Register(protocol Protocol) {
	r.protocols[protocol.Name()] = protocol
	r.schemeHandlers[protocol.Scheme()] = protocol
}

// Get gets a protocol handler by name
func (r *ProtocolRegistry) Get(name string) (Protocol, bool) {
	protocol, exists := r.protocols[name]
	return protocol, exists
}

// GetByScheme gets a protocol handler by scheme
func (r *ProtocolRegistry) GetByScheme(scheme string) (Protocol, bool) {
	protocol, exists := r.schemeHandlers[scheme]
	return protocol, exists
}

// GetForRequest gets the appropriate protocol handler for a request
func (r *ProtocolRegistry) GetForRequest(req *Request) (Protocol, error) {
	for _, protocol := range r.protocols {
		if protocol.CanHandle(req) {
			return protocol, nil
		}
	}
	
	return nil, fmt.Errorf("no protocol handler found for request: %s", req.URL)
}

// Execute executes a request using the appropriate protocol handler
func (r *ProtocolRegistry) Execute(req *Request) (*Response, error) {
	protocol, err := r.GetForRequest(req)
	if err != nil {
		return nil, err
	}
	
	return protocol.Execute(req)
}

// ProtocolFactory creates protocol handlers
type ProtocolFactory struct {
	// registry is the protocol registry
	registry *ProtocolRegistry
}

// NewProtocolFactory creates a new protocol factory
func NewProtocolFactory() *ProtocolFactory {
	return &ProtocolFactory{
		registry: NewProtocolRegistry(),
	}
}

// CreateHTTPProtocol creates an HTTP protocol handler
func (f *ProtocolFactory) CreateHTTPProtocol(client *http.Client) Protocol {
	protocol := NewHTTPProtocol(client)
	f.registry.Register(protocol)
	return protocol
}

// CreateWebSocketProtocol creates a WebSocket protocol handler
func (f *ProtocolFactory) CreateWebSocketProtocol() Protocol {
	protocol := NewWebSocketProtocol()
	f.registry.Register(protocol)
	return protocol
}

// CreateGraphQLProtocol creates a GraphQL protocol handler
func (f *ProtocolFactory) CreateGraphQLProtocol(client *http.Client) Protocol {
	protocol := NewGraphQLProtocol(client)
	f.registry.Register(protocol)
	return protocol
}

// CreateGRPCProtocol creates a gRPC protocol handler
func (f *ProtocolFactory) CreateGRPCProtocol() Protocol {
	protocol := NewGRPCProtocol()
	f.registry.Register(protocol)
	return protocol
}

// GetRegistry gets the protocol registry
func (f *ProtocolFactory) GetRegistry() *ProtocolRegistry {
	return f.registry
}

// CreateDefaultProtocols creates the default protocol handlers
func (f *ProtocolFactory) CreateDefaultProtocols(client *http.Client) {
	f.CreateHTTPProtocol(client)
	f.CreateWebSocketProtocol()
	f.CreateGraphQLProtocol(client)
	f.CreateGRPCProtocol()
}
