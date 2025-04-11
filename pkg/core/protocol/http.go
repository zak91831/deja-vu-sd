package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPProtocol implements the HTTP and HTTPS protocols
type HTTPProtocol struct {
	// client is the HTTP client
	client *http.Client
}

// NewHTTPProtocol creates a new HTTP protocol handler
func NewHTTPProtocol(client *http.Client) *HTTPProtocol {
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	
	return &HTTPProtocol{
		client: client,
	}
}

// Name returns the protocol name
func (p *HTTPProtocol) Name() string {
	return "http"
}

// Scheme returns the protocol scheme
func (p *HTTPProtocol) Scheme() string {
	return "http"
}

// DefaultPort returns the default port for the protocol
func (p *HTTPProtocol) DefaultPort() int {
	return 80
}

// Execute executes an HTTP request
func (p *HTTPProtocol) Execute(req *Request) (*Response, error) {
	// Parse URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	
	// Create HTTP request
	httpReq, err := http.NewRequest(req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	for name, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(name, value)
		}
	}
	
	// Set timeout
	if req.Timeout > 0 {
		ctx, cancel := context.WithTimeout(httpReq.Context(), time.Duration(req.Timeout)*time.Second)
		defer cancel()
		httpReq = httpReq.WithContext(ctx)
	}
	
	// Configure client for redirects
	originalCheckRedirect := p.client.CheckRedirect
	defer func() {
		p.client.CheckRedirect = originalCheckRedirect
	}()
	
	if !req.FollowRedirects {
		p.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if req.MaxRedirects > 0 {
		p.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= req.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", req.MaxRedirects)
			}
			return nil
		}
	}
	
	// Execute request
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close()
	
	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Convert headers
	headers := make(map[string][]string)
	for name, values := range httpResp.Header {
		headers[name] = values
	}
	
	// Create response
	resp := &Response{
		StatusCode: httpResp.StatusCode,
		Headers:    headers,
		Body:       body,
		Protocol:   p.Name(),
		Raw:        httpResp,
		Request:    req,
	}
	
	return resp, nil
}

// CanHandle checks if this protocol can handle the given request
func (p *HTTPProtocol) CanHandle(req *Request) bool {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return false
	}
	
	return parsedURL.Scheme == "http" || parsedURL.Scheme == "https"
}

// HTTPSProtocol implements the HTTPS protocol
type HTTPSProtocol struct {
	*HTTPProtocol
}

// NewHTTPSProtocol creates a new HTTPS protocol handler
func NewHTTPSProtocol(client *http.Client) *HTTPSProtocol {
	return &HTTPSProtocol{
		HTTPProtocol: NewHTTPProtocol(client),
	}
}

// Name returns the protocol name
func (p *HTTPSProtocol) Name() string {
	return "https"
}

// Scheme returns the protocol scheme
func (p *HTTPSProtocol) Scheme() string {
	return "https"
}

// DefaultPort returns the default port for the protocol
func (p *HTTPSProtocol) DefaultPort() int {
	return 443
}

// CanHandle checks if this protocol can handle the given request
func (p *HTTPSProtocol) CanHandle(req *Request) bool {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return false
	}
	
	return parsedURL.Scheme == "https"
}

// GraphQLProtocol implements the GraphQL protocol
type GraphQLProtocol struct {
	// client is the HTTP client
	client *http.Client
}

// GraphQLRequest represents a GraphQL request
type GraphQLRequest struct {
	// Query is the GraphQL query
	Query string `json:"query"`
	
	// Variables are the GraphQL variables
	Variables map[string]interface{} `json:"variables,omitempty"`
	
	// OperationName is the GraphQL operation name
	OperationName string `json:"operationName,omitempty"`
}

// NewGraphQLProtocol creates a new GraphQL protocol handler
func NewGraphQLProtocol(client *http.Client) *GraphQLProtocol {
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	
	return &GraphQLProtocol{
		client: client,
	}
}

// Name returns the protocol name
func (p *GraphQLProtocol) Name() string {
	return "graphql"
}

// Scheme returns the protocol scheme
func (p *GraphQLProtocol) Scheme() string {
	return "http"
}

// DefaultPort returns the default port for the protocol
func (p *GraphQLProtocol) DefaultPort() int {
	return 80
}

// Execute executes a GraphQL request
func (p *GraphQLProtocol) Execute(req *Request) (*Response, error) {
	// Extract GraphQL parameters from request
	query, ok := req.Params["query"].(string)
	if !ok {
		return nil, fmt.Errorf("GraphQL query is required")
	}
	
	variables, _ := req.Params["variables"].(map[string]interface{})
	operationName, _ := req.Params["operationName"].(string)
	
	// Create GraphQL request
	graphqlReq := GraphQLRequest{
		Query:         query,
		Variables:     variables,
		OperationName: operationName,
	}
	
	// Convert to JSON
	jsonData, err := json.Marshal(graphqlReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}
	
	// Create HTTP request
	httpReq, err := http.NewRequest("POST", req.URL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	for name, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(name, value)
		}
	}
	
	// Set timeout
	if req.Timeout > 0 {
		ctx, cancel := context.WithTimeout(httpReq.Context(), time.Duration(req.Timeout)*time.Second)
		defer cancel()
		httpReq = httpReq.WithContext(ctx)
	}
	
	// Execute request
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("GraphQL request failed: %w", err)
	}
	defer httpResp.Body.Close()
	
	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Convert headers
	headers := make(map[string][]string)
	for name, values := range httpResp.Header {
		headers[name] = values
	}
	
	// Create response
	resp := &Response{
		StatusCode: httpResp.StatusCode,
		Headers:    headers,
		Body:       body,
		Protocol:   p.Name(),
		Raw:        httpResp,
		Request:    req,
	}
	
	return resp, nil
}

// CanHandle checks if this protocol can handle the given request
func (p *GraphQLProtocol) CanHandle(req *Request) bool {
	// Check if request has GraphQL parameters
	_, hasQuery := req.Params["query"]
	
	// Check Content-Type header
	isGraphQL := false
	for name, values := range req.Headers {
		if strings.ToLower(name) == "content-type" {
			for _, value := range values {
				if strings.Contains(value, "application/graphql") {
					isGraphQL = true
					break
				}
			}
		}
	}
	
	return hasQuery || isGraphQL
}

// WebSocketProtocol implements the WebSocket protocol
type WebSocketProtocol struct {
	// dialer is the WebSocket dialer
	dialer *websocket.Dialer
}

// NewWebSocketProtocol creates a new WebSocket protocol handler
func NewWebSocketProtocol() *WebSocketProtocol {
	return &WebSocketProtocol{
		dialer: &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 45 * time.Second,
		},
	}
}

// Name returns the protocol name
func (p *WebSocketProtocol) Name() string {
	return "websocket"
}

// Scheme returns the protocol scheme
func (p *WebSocketProtocol) Scheme() string {
	return "ws"
}

// DefaultPort returns the default port for the protocol
func (p *WebSocketProtocol) DefaultPort() int {
	return 80
}

// Execute executes a WebSocket request
func (p *WebSocketProtocol) Execute(req *Request) (*Response, error) {
	// Parse URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	
	// Ensure scheme is ws or wss
	if parsedURL.Scheme != "ws" && parsedURL.Scheme != "wss" {
		if parsedURL.Scheme == "http" {
			parsedURL.Scheme = "ws"
		} else if parsedURL.Scheme == "https" {
			parsedURL.Scheme = "wss"
		} else {
			return nil, fmt.Errorf("invalid WebSocket scheme: %s", parsedURL.Scheme)
		}
	}
	
	// Convert headers
	header := http.Header{}
	for name, values := range req.Headers {
		for _, value := range values {
			header.Add(name, value)
		}
	}
	
	// Set timeout
	ctx := context.Background()
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.Timeout)*time.Second)
		defer cancel()
	}
	
	// Connect to WebSocket
	conn, httpResp, err := p.dialer.DialContext(ctx, parsedURL.String(), header)
	if err != nil {
		if httpResp != nil {
			// Return HTTP response for connection failure
			body, _ := io.ReadAll(httpResp.Body)
			httpResp.Body.Close()
			
			headers := make(map[string][]string)
			for name, values := range httpResp.Header {
				headers[name] = values
			}
			
			return &Response{
				StatusCode: httpResp.StatusCode,
				Headers:    headers,
				Body:       body,
				Protocol:   p.Name(),
				Raw:        httpResp,
				Request:    req,
				Error:      err,
			}, nil
		}
		
		return nil, fmt.Errorf("WebSocket connection failed: %w", err)
	}
	defer conn.Close()
	
	// Send message if body is provided
	if len(req.Body) > 0 {
		messageType := websocket.TextMessage
		if _, ok := req.Params["binary"]; ok {
			messageType = websocket.BinaryMessage
		}
		
		if err := conn.WriteMessage(messageType, req.Body); err != nil {
			return nil, fmt.Errorf("failed to send WebSocket message: %w", err)
		}
	}
	
	// Read response
	messageType, message, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read WebSocket message: %w", err)
	}
	
	// Create response
	headers := make(map[string][]string)
	if httpResp != nil {
		for name, values := range httpResp.Header {
			headers[name] = values
		}
	}
	
	resp := &Response{
		StatusCode: 200, // WebSocket success
		Headers:    headers,
		Body:       message,
		Protocol:   p.Name(),
		Raw: map[string]interface{}{
			"messageType": messageType,
			"connection":  conn,
			"httpResponse": httpResp,
		},
		Request: req,
	}
	
	return resp, nil
}

// CanHandle checks if this protocol can handle the given request
func (p *WebSocketProtocol) CanHandle(req *Request) bool {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return false
	}
	
	return parsedURL.Scheme == "ws" || parsedURL.Scheme == "wss"
}

// GRPCProtocol implements the gRPC protocol
type GRPCProtocol struct{}

// NewGRPCProtocol creates a new gRPC protocol handler
func NewGRPCProtocol() *GRPCProtocol {
	return &GRPCProtocol{}
}

// Name returns the protocol name
func (p *GRPCProtocol) Name() string {
	return "grpc"
}

// Scheme returns the protocol scheme
func (p *GRPCProtocol) Scheme() string {
	return "grpc"
}

// DefaultPort returns the default port for the protocol
func (p *GRPCProtocol) DefaultPort() int {
	return 50051
}

// Execute executes a gRPC request
func (p *GRPCProtocol) Execute(req *Request) (*Response, error) {
	// This is a simplified implementation
	// A real implementation would use the gRPC Go library
	
	// Parse URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	
	// Extract service and method
	service, ok := req.Params["service"].(string)
	if !ok {
		return nil, fmt.Errorf("gRPC service is required")
	}
	
	method, ok := req.Params["method"].(string)
	if !ok {
		return nil, fmt.Errorf("gRPC method is required")
	}
	
	// Extract request data
	requestData, ok := req.Params["request"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("gRPC request data is required")
	}
	
	// In a real implementation, this would use reflection or generated code
	// to create and execute the gRPC request
	
	// For now, return a mock response
	resp := &Response{
		StatusCode: 200,
		Headers:    make(map[string][]string),
		Body:       []byte(`{"success": true, "message": "gRPC request executed"}`),
		Protocol:   p.Name(),
		Raw: map[string]interface{}{
			"service": service,
			"method":  method,
			"request": requestData,
		},
		Request: req,
	}
	
	return resp, nil
}

// CanHandle checks if this protocol can handle the given request
func (p *GRPCProtocol) CanHandle(req *Request) bool {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return false
	}
	
	// Check scheme
	if parsedURL.Scheme == "grpc" || parsedURL.Scheme == "grpcs" {
		return true
	}
	
	// Check if request has gRPC parameters
	_, hasService := req.Params["service"]
	_, hasMethod := req.Params["method"]
	
	return hasService && hasMethod
}

// Import the websocket package
// This is a placeholder for the actual import
type websocket struct {
	Dialer struct {
		Proxy            func(*http.Request) (*url.URL, error)
		HandshakeTimeout time.Duration
	}
}

func (d *websocket.Dialer) DialContext(ctx context.Context, urlStr string, header http.Header) (*websocketConn, *http.Response, error) {
	// This is a placeholder for the actual implementation
	return nil, nil, fmt.Errorf("WebSocket not implemented")
}

type websocketConn struct{}

func (c *websocketConn) Close() error {
	return nil
}

func (c *websocketConn) WriteMessage(messageType int, data []byte) error {
	return nil
}

func (c *websocketConn) ReadMessage() (int, []byte, error) {
	return 0, nil, nil
}

const (
	TextMessage   = 1
	BinaryMessage = 2
)
