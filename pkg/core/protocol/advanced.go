package protocol

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RESTProtocol implements the REST API protocol
type RESTProtocol struct {
	// client is the HTTP client
	client *http.Client
}

// NewRESTProtocol creates a new REST protocol handler
func NewRESTProtocol(client *http.Client) *RESTProtocol {
	if client == nil {
		client = &http.Client{}
	}
	
	return &RESTProtocol{
		client: client,
	}
}

// Name returns the protocol name
func (p *RESTProtocol) Name() string {
	return "rest"
}

// Scheme returns the protocol scheme
func (p *RESTProtocol) Scheme() string {
	return "http"
}

// DefaultPort returns the default port for the protocol
func (p *RESTProtocol) DefaultPort() int {
	return 80
}

// Execute executes a REST request
func (p *RESTProtocol) Execute(req *Request) (*Response, error) {
	// Create HTTP request
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(string(req.Body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	for name, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(name, value)
		}
	}
	
	// Set content type if not already set
	if httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	
	// Set accept header if not already set
	if httpReq.Header.Get("Accept") == "" {
		httpReq.Header.Set("Accept", "application/json")
	}
	
	// Execute request
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("REST request failed: %w", err)
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
func (p *RESTProtocol) CanHandle(req *Request) bool {
	// Check if request has REST parameters
	_, isREST := req.Params["rest"]
	
	// Check Content-Type and Accept headers
	hasRESTHeaders := false
	for name, values := range req.Headers {
		if strings.ToLower(name) == "content-type" || strings.ToLower(name) == "accept" {
			for _, value := range values {
				if strings.Contains(value, "application/json") {
					hasRESTHeaders = true
					break
				}
			}
		}
	}
	
	return isREST || hasRESTHeaders
}

// SOAPProtocol implements the SOAP protocol
type SOAPProtocol struct {
	// client is the HTTP client
	client *http.Client
}

// NewSOAPProtocol creates a new SOAP protocol handler
func NewSOAPProtocol(client *http.Client) *SOAPProtocol {
	if client == nil {
		client = &http.Client{}
	}
	
	return &SOAPProtocol{
		client: client,
	}
}

// Name returns the protocol name
func (p *SOAPProtocol) Name() string {
	return "soap"
}

// Scheme returns the protocol scheme
func (p *SOAPProtocol) Scheme() string {
	return "http"
}

// DefaultPort returns the default port for the protocol
func (p *SOAPProtocol) DefaultPort() int {
	return 80
}

// Execute executes a SOAP request
func (p *SOAPProtocol) Execute(req *Request) (*Response, error) {
	// Extract SOAP parameters
	action, _ := req.Params["soapAction"].(string)
	
	// Create HTTP request
	httpReq, err := http.NewRequest("POST", req.URL, strings.NewReader(string(req.Body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	for name, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(name, value)
		}
	}
	
	// Set content type if not already set
	if httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "text/xml; charset=utf-8")
	}
	
	// Set SOAPAction header if provided
	if action != "" {
		httpReq.Header.Set("SOAPAction", action)
	}
	
	// Execute request
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("SOAP request failed: %w", err)
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
func (p *SOAPProtocol) CanHandle(req *Request) bool {
	// Check if request has SOAP parameters
	_, isSOAP := req.Params["soap"]
	_, hasSOAPAction := req.Params["soapAction"]
	
	// Check Content-Type header
	hasSOAPHeader := false
	for name, values := range req.Headers {
		if strings.ToLower(name) == "content-type" {
			for _, value := range values {
				if strings.Contains(value, "text/xml") {
					hasSOAPHeader = true
					break
				}
			}
		}
	}
	
	// Check if body contains SOAP envelope
	hasSOAPEnvelope := false
	if len(req.Body) > 0 {
		bodyStr := string(req.Body)
		hasSOAPEnvelope = strings.Contains(bodyStr, "Envelope") && 
						  (strings.Contains(bodyStr, "xmlns:soap") || 
						   strings.Contains(bodyStr, "xmlns:SOAP"))
	}
	
	return isSOAP || hasSOAPAction || (hasSOAPHeader && hasSOAPEnvelope)
}

// ODataProtocol implements the OData protocol
type ODataProtocol struct {
	// client is the HTTP client
	client *http.Client
}

// NewODataProtocol creates a new OData protocol handler
func NewODataProtocol(client *http.Client) *ODataProtocol {
	if client == nil {
		client = &http.Client{}
	}
	
	return &ODataProtocol{
		client: client,
	}
}

// Name returns the protocol name
func (p *ODataProtocol) Name() string {
	return "odata"
}

// Scheme returns the protocol scheme
func (p *ODataProtocol) Scheme() string {
	return "http"
}

// DefaultPort returns the default port for the protocol
func (p *ODataProtocol) DefaultPort() int {
	return 80
}

// Execute executes an OData request
func (p *ODataProtocol) Execute(req *Request) (*Response, error) {
	// Create HTTP request
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(string(req.Body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	for name, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(name, value)
		}
	}
	
	// Set OData-specific headers if not already set
	if httpReq.Header.Get("Accept") == "" {
		httpReq.Header.Set("Accept", "application/json;odata.metadata=minimal")
	}
	
	// Execute request
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OData request failed: %w", err)
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
func (p *ODataProtocol) CanHandle(req *Request) bool {
	// Check if request has OData parameters
	_, isOData := req.Params["odata"]
	
	// Check URL for OData patterns
	hasODataURL := false
	if strings.Contains(req.URL, "$filter=") || 
	   strings.Contains(req.URL, "$select=") || 
	   strings.Contains(req.URL, "$expand=") || 
	   strings.Contains(req.URL, "$orderby=") || 
	   strings.Contains(req.URL, "$top=") || 
	   strings.Contains(req.URL, "$skip=") {
		hasODataURL = true
	}
	
	// Check headers for OData patterns
	hasODataHeaders := false
	for name, values := range req.Headers {
		if strings.ToLower(name) == "accept" {
			for _, value := range values {
				if strings.Contains(value, "odata") {
					hasODataHeaders = true
					break
				}
			}
		}
	}
	
	return isOData || hasODataURL || hasODataHeaders
}

// JSONRPCProtocol implements the JSON-RPC protocol
type JSONRPCProtocol struct {
	// client is the HTTP client
	client *http.Client
}

// JSONRPCRequest represents a JSON-RPC request
type JSONRPCRequest struct {
	// JSONRPC is the JSON-RPC version
	JSONRPC string `json:"jsonrpc"`
	
	// Method is the method to call
	Method string `json:"method"`
	
	// Params are the method parameters
	Params interface{} `json:"params,omitempty"`
	
	// ID is the request ID
	ID interface{} `json:"id,omitempty"`
}

// NewJSONRPCProtocol creates a new JSON-RPC protocol handler
func NewJSONRPCProtocol(client *http.Client) *JSONRPCProtocol {
	if client == nil {
		client = &http.Client{}
	}
	
	return &JSONRPCProtocol{
		client: client,
	}
}

// Name returns the protocol name
func (p *JSONRPCProtocol) Name() string {
	return "jsonrpc"
}

// Scheme returns the protocol scheme
func (p *JSONRPCProtocol) Scheme() string {
	return "http"
}

// DefaultPort returns the default port for the protocol
func (p *JSONRPCProtocol) DefaultPort() int {
	return 80
}

// Execute executes a JSON-RPC request
func (p *JSONRPCProtocol) Execute(req *Request) (*Response, error) {
	// Extract JSON-RPC parameters
	method, _ := req.Params["method"].(string)
	params, _ := req.Params["params"]
	id, _ := req.Params["id"]
	
	var jsonrpcReq JSONRPCRequest
	
	// If body is provided, try to parse it as a JSON-RPC request
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &jsonrpcReq); err == nil {
			// Body is a valid JSON-RPC request
			if method != "" {
				jsonrpcReq.Method = method
			}
			if params != nil {
				jsonrpcReq.Params = params
			}
			if id != nil {
				jsonrpcReq.ID = id
			}
		} else {
			// Create new JSON-RPC request
			jsonrpcReq = JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  params,
				ID:      id,
			}
		}
	} else {
		// Create new JSON-RPC request
		jsonrpcReq = JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  method,
			Params:  params,
			ID:      id,
		}
	}
	
	// Convert to JSON
	jsonData, err := json.Marshal(jsonrpcReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON-RPC request: %w", err)
	}
	
	// Create HTTP request
	httpReq, err := http.NewRequest("POST", req.URL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	for name, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(name, value)
		}
	}
	
	// Set content type if not already set
	if httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	
	// Execute request
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("JSON-RPC request failed: %w", err)
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
func (p *JSONRPCProtocol) CanHandle(req *Request) bool {
	// Check if request has JSON-RPC parameters
	_, isJSONRPC := req.Params["jsonrpc"]
	_, hasMethod := req.Params["method"]
	
	// Check if body contains JSON-RPC structure
	hasJSONRPCBody := false
	if len(req.Body) > 0 {
		var jsonrpcReq map[string]interface{}
		if err := json.Unmarshal(req.Body, &jsonrpcReq); err == nil {
			_, hasJSONRPC := jsonrpcReq["jsonrpc"]
			_, hasMethod := jsonrpcReq["method"]
			hasJSONRPCBody = hasJSONRPC && hasMethod
		}
	}
	
	return isJSONRPC || (hasMethod && req.Method == "POST") || hasJSONRPCBody
}

// ProtocolUtils provides utility functions for protocols
type ProtocolUtils struct{}

// NewProtocolUtils creates a new protocol utils
func NewProtocolUtils() *ProtocolUtils {
	return &ProtocolUtils{}
}

// ParseURL parses a URL and ensures it's valid
func (u *ProtocolUtils) ParseURL(urlStr string) (*url.URL, error) {
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}
	
	return url.Parse(urlStr)
}

// GetProtocolFromURL gets the protocol from a URL
func (u *ProtocolUtils) GetProtocolFromURL(urlStr string) (string, error) {
	parsedURL, err := u.ParseURL(urlStr)
	if err != nil {
		return "", err
	}
	
	return parsedURL.Scheme, nil
}

// IsWebSocketURL checks if a URL is a WebSocket URL
func (u *ProtocolUtils) IsWebSocketURL(urlStr string) bool {
	protocol, err := u.GetProtocolFromURL(urlStr)
	if err != nil {
		return false
	}
	
	return protocol == "ws" || protocol == "wss"
}

// IsHTTPURL checks if a URL is an HTTP URL
func (u *ProtocolUtils) IsHTTPURL(urlStr string) bool {
	protocol, err := u.GetProtocolFromURL(urlStr)
	if err != nil {
		return false
	}
	
	return protocol == "http" || protocol == "https"
}

// IsGRPCURL checks if a URL is a gRPC URL
func (u *ProtocolUtils) IsGRPCURL(urlStr string) bool {
	protocol, err := u.GetProtocolFromURL(urlStr)
	if err != nil {
		return false
	}
	
	return protocol == "grpc" || protocol == "grpcs"
}

// GetDefaultPort gets the default port for a protocol
func (u *ProtocolUtils) GetDefaultPort(protocol string) int {
	switch protocol {
	case "http":
		return 80
	case "https":
		return 443
	case "ws":
		return 80
	case "wss":
		return 443
	case "grpc":
		return 50051
	case "grpcs":
		return 50052
	default:
		return 0
	}
}

// CreateProtocolRequest creates a protocol-agnostic request
func (u *ProtocolUtils) CreateProtocolRequest(url, method string, headers map[string][]string, body []byte) *Request {
	return &Request{
		URL:     url,
		Method:  method,
		Headers: headers,
		Body:    body,
		Params:  make(map[string]interface{}),
	}
}
