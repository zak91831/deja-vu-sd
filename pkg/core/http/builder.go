package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// RequestBuilder helps build HTTP requests with a fluent API
type RequestBuilder struct {
	// request is the request being built
	request *Request
	
	// client is the HTTP client to use
	client *Client
	
	// err stores any error that occurred during building
	err error
}

// NewRequestBuilder creates a new request builder
func NewRequestBuilder(client *Client) *RequestBuilder {
	return &RequestBuilder{
		request: &Request{
			Method:  "GET",
			Headers: make(map[string]string),
			Cookies: make([]*http.Cookie, 0),
		},
		client: client,
	}
}

// Method sets the HTTP method
func (b *RequestBuilder) Method(method string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.Method = method
	return b
}

// URL sets the target URL
func (b *RequestBuilder) URL(url string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.URL = url
	return b
}

// Header adds a header
func (b *RequestBuilder) Header(key, value string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	if b.request.Headers == nil {
		b.request.Headers = make(map[string]string)
	}
	
	b.request.Headers[key] = value
	return b
}

// Headers adds multiple headers
func (b *RequestBuilder) Headers(headers map[string]string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	if b.request.Headers == nil {
		b.request.Headers = make(map[string]string)
	}
	
	for key, value := range headers {
		b.request.Headers[key] = value
	}
	
	return b
}

// Cookie adds a cookie
func (b *RequestBuilder) Cookie(cookie *http.Cookie) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.Cookies = append(b.request.Cookies, cookie)
	return b
}

// CookieByNameValue adds a cookie by name and value
func (b *RequestBuilder) CookieByNameValue(name, value string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	cookie := &http.Cookie{
		Name:  name,
		Value: value,
	}
	
	b.request.Cookies = append(b.request.Cookies, cookie)
	return b
}

// Body sets the request body
func (b *RequestBuilder) Body(body io.Reader) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.Body = body
	return b
}

// BodyBytes sets the request body as bytes
func (b *RequestBuilder) BodyBytes(body []byte) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.BodyBytes = body
	return b
}

// BodyString sets the request body as string
func (b *RequestBuilder) BodyString(body string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.BodyString = body
	return b
}

// BodyJSON sets the request body as JSON
func (b *RequestBuilder) BodyJSON(body interface{}) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.BodyJSON = body
	b.Header("Content-Type", "application/json")
	return b
}

// BodyForm sets the request body as form values
func (b *RequestBuilder) BodyForm(form url.Values) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.BodyForm = form
	b.Header("Content-Type", "application/x-www-form-urlencoded")
	return b
}

// FormValue adds a form value
func (b *RequestBuilder) FormValue(key, value string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	if b.request.BodyForm == nil {
		b.request.BodyForm = make(url.Values)
	}
	
	b.request.BodyForm.Add(key, value)
	b.Header("Content-Type", "application/x-www-form-urlencoded")
	return b
}

// MultipartForm creates a multipart form request
func (b *RequestBuilder) MultipartForm() *MultipartFormBuilder {
	if b.err != nil {
		return &MultipartFormBuilder{err: b.err}
	}
	
	return &MultipartFormBuilder{
		requestBuilder: b,
		formData:       make(map[string]string),
		formFiles:      make(map[string]string),
	}
}

// Timeout sets the request timeout
func (b *RequestBuilder) Timeout(timeout int) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.Timeout = timeout
	return b
}

// SessionID sets the session ID
func (b *RequestBuilder) SessionID(sessionID string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	
	b.request.SessionID = sessionID
	return b
}

// Build builds the request
func (b *RequestBuilder) Build() (*Request, error) {
	if b.err != nil {
		return nil, b.err
	}
	
	return b.request, nil
}

// Send builds and sends the request
func (b *RequestBuilder) Send() (*Response, error) {
	if b.err != nil {
		return nil, b.err
	}
	
	return b.client.Do(b.request)
}

// MultipartFormBuilder helps build multipart form requests
type MultipartFormBuilder struct {
	// requestBuilder is the parent request builder
	requestBuilder *RequestBuilder
	
	// formData contains form field data
	formData map[string]string
	
	// formFiles contains file paths to upload
	formFiles map[string]string
	
	// err stores any error that occurred during building
	err error
}

// Field adds a form field
func (b *MultipartFormBuilder) Field(name, value string) *MultipartFormBuilder {
	if b.err != nil {
		return b
	}
	
	b.formData[name] = value
	return b
}

// File adds a file to upload
func (b *MultipartFormBuilder) File(fieldName, filePath string) *MultipartFormBuilder {
	if b.err != nil {
		return b
	}
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		b.err = fmt.Errorf("file not found: %s", filePath)
		return b
	}
	
	b.formFiles[fieldName] = filePath
	return b
}

// Build builds the multipart form request
func (b *MultipartFormBuilder) Build() (*RequestBuilder, error) {
	if b.err != nil {
		return nil, b.err
	}
	
	// Create multipart writer
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	// Add form fields
	for name, value := range b.formData {
		if err := writer.WriteField(name, value); err != nil {
			return nil, fmt.Errorf("failed to write form field: %w", err)
		}
	}
	
	// Add files
	for fieldName, filePath := range b.formFiles {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()
		
		// Create form file
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fieldName, filepath.Base(filePath)))
		h.Set("Content-Type", getContentType(filePath))
		
		part, err := writer.CreatePart(h)
		if err != nil {
			return nil, fmt.Errorf("failed to create form file: %w", err)
		}
		
		// Copy file content
		if _, err := io.Copy(part, file); err != nil {
			return nil, fmt.Errorf("failed to copy file content: %w", err)
		}
	}
	
	// Close writer
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}
	
	// Set content type and body
	b.requestBuilder.Header("Content-Type", writer.FormDataContentType())
	b.requestBuilder.BodyBytes(body.Bytes())
	
	return b.requestBuilder, nil
}

// End builds the multipart form request and returns to the request builder
func (b *MultipartFormBuilder) End() *RequestBuilder {
	rb, err := b.Build()
	if err != nil {
		return &RequestBuilder{err: err}
	}
	
	return rb
}

// getContentType guesses the content type of a file
func getContentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	switch ext {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain"
	case ".html", ".htm":
		return "text/html"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".zip":
		return "application/zip"
	default:
		return "application/octet-stream"
	}
}

// ResponseProcessor helps process HTTP responses
type ResponseProcessor struct {
	// response is the response being processed
	response *Response
	
	// err stores any error that occurred during processing
	err error
}

// NewResponseProcessor creates a new response processor
func NewResponseProcessor(response *Response) *ResponseProcessor {
	return &ResponseProcessor{
		response: response,
	}
}

// JSON unmarshals the response body as JSON
func (p *ResponseProcessor) JSON(v interface{}) error {
	if p.err != nil {
		return p.err
	}
	
	if p.response == nil {
		return fmt.Errorf("response is nil")
	}
	
	return json.Unmarshal(p.response.Body, v)
}

// String returns the response body as string
func (p *ResponseProcessor) String() (string, error) {
	if p.err != nil {
		return "", p.err
	}
	
	if p.response == nil {
		return "", fmt.Errorf("response is nil")
	}
	
	return string(p.response.Body), nil
}

// Bytes returns the response body as bytes
func (p *ResponseProcessor) Bytes() ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	
	if p.response == nil {
		return nil, fmt.Errorf("response is nil")
	}
	
	return p.response.Body, nil
}

// SaveToFile saves the response body to a file
func (p *ResponseProcessor) SaveToFile(filePath string) error {
	if p.err != nil {
		return p.err
	}
	
	if p.response == nil {
		return fmt.Errorf("response is nil")
	}
	
	return os.WriteFile(filePath, p.response.Body, 0644)
}

// Header returns a response header
func (p *ResponseProcessor) Header(key string) string {
	if p.err != nil {
		return ""
	}
	
	if p.response == nil {
		p.err = fmt.Errorf("response is nil")
		return ""
	}
	
	return p.response.Headers.Get(key)
}

// StatusCode returns the response status code
func (p *ResponseProcessor) StatusCode() int {
	if p.err != nil {
		return 0
	}
	
	if p.response == nil {
		p.err = fmt.Errorf("response is nil")
		return 0
	}
	
	return p.response.StatusCode
}

// IsSuccess returns true if the response status code is 2xx
func (p *ResponseProcessor) IsSuccess() bool {
	return p.StatusCode() >= 200 && p.StatusCode() < 300
}

// IsRedirect returns true if the response status code is 3xx
func (p *ResponseProcessor) IsRedirect() bool {
	return p.StatusCode() >= 300 && p.StatusCode() < 400
}

// IsClientError returns true if the response status code is 4xx
func (p *ResponseProcessor) IsClientError() bool {
	return p.StatusCode() >= 400 && p.StatusCode() < 500
}

// IsServerError returns true if the response status code is 5xx
func (p *ResponseProcessor) IsServerError() bool {
	return p.StatusCode() >= 500 && p.StatusCode() < 600
}

// Error returns an error if the response status code is not 2xx
func (p *ResponseProcessor) Error() error {
	if p.err != nil {
		return p.err
	}
	
	if p.response == nil {
		return fmt.Errorf("response is nil")
	}
	
	if !p.IsSuccess() {
		return fmt.Errorf("HTTP error: %s", p.response.Status)
	}
	
	return nil
}
