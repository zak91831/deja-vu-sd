# Developer Guide

This guide provides detailed information for developers who want to extend or contribute to the Deja Vu vulnerability scanner.

## Project Structure

```
deja_vu/
├── cmd/                    # Command-line applications
│   └── deja_vu/            # Main application
├── pkg/                    # Core packages
│   ├── core/               # Core functionality
│   │   ├── engine/         # Scanner engine
│   │   ├── execution/      # Execution engine
│   │   ├── extractor/      # Data extraction
│   │   ├── http/           # HTTP client
│   │   ├── matcher/        # Pattern matching
│   │   ├── protocol/       # Protocol handlers
│   │   ├── result/         # Result processing
│   │   └── target/         # Target handling
│   ├── adaptive/           # Adaptive learning
│   ├── detection/          # Detection mechanisms
│   ├── integration/        # Integration framework
│   ├── persona/            # Personality-driven scanning
│   ├── plugins/            # Plugin system
│   ├── template/           # Template system
│   └── timetravel/         # Time-travel scanning
├── internal/               # Internal packages
│   ├── config/             # Configuration
│   ├── logger/             # Logging
│   └── utils/              # Utilities
├── templates/              # Vulnerability templates
├── scripts/                # Utility scripts
└── test/                   # Test suite
```

## Architecture Overview

Deja Vu follows a modular, plugin-based architecture with the following key components:

1. **Core Engine**: Handles scanning operations, template execution, and result processing
2. **Plugin System**: Provides extensibility for advanced features
3. **Integration Layer**: Connects all components through a unified API

### Component Interaction

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    CLI      │────▶│  Core Engine│────▶│   Results   │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Integration │
                    └──────┬──────┘
                           │
        ┌────────────┬─────┴─────┬────────────┐
        ▼            ▼           ▼            ▼
┌─────────────┐┌─────────────┐┌─────────────┐┌─────────────┐
│  Time-Travel││   Persona   ││   Adaptive  ││    Other    │
│   Scanning  ││   Scanning  ││   Learning  ││   Plugins   │
└─────────────┘└─────────────┘└─────────────┘└─────────────┘
```

## Development Environment Setup

### Prerequisites

- Go 1.18 or higher
- Git
- Make (optional, for build scripts)
- Docker (optional, for containerized development)

### Setting Up Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/dejavu/scanner.git
   cd scanner
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Build the project:
   ```bash
   go build -o dejavu ./cmd/deja_vu
   ```

4. Run tests:
   ```bash
   go test ./...
   ```

### Development with Docker

1. Build the development container:
   ```bash
   docker build -t dejavu-dev -f Dockerfile.dev .
   ```

2. Run the development container:
   ```bash
   docker run -it -v $(pwd):/app dejavu-dev bash
   ```

## Extending Deja Vu

### Creating a New Plugin

1. Create a new package in `pkg/`:
   ```bash
   mkdir -p pkg/myplugin
   ```

2. Implement the plugin interface:
   ```go
   // pkg/myplugin/plugin.go
   package myplugin

   import (
       "fmt"
   )

   // Plugin represents a custom plugin
   type Plugin struct {
       // Plugin configuration
       Config *Config
   }

   // Config contains plugin configuration
   type Config struct {
       // Configuration fields
       Enabled bool
       Options map[string]interface{}
   }

   // NewPlugin creates a new plugin
   func NewPlugin(config *Config) *Plugin {
       return &Plugin{
           Config: config,
       }
   }

   // Execute executes the plugin
   func (p *Plugin) Execute(target string) (interface{}, error) {
       // Plugin implementation
       return fmt.Sprintf("Executed plugin on %s", target), nil
   }
   ```

3. Register the plugin in the integration layer:
   ```go
   // pkg/integration/adapters.go (add to existing file)
   
   // MyPluginAdapter adapts the custom plugin to the Component interface
   type MyPluginAdapter struct {
       // Plugin is the custom plugin
       Plugin interface{} // Replace with actual plugin type
       
       // Options contains adapter options
       Options map[string]interface{}
   }
   
   // NewMyPluginAdapter creates a new custom plugin adapter
   func NewMyPluginAdapter(plugin interface{}, options map[string]interface{}) *MyPluginAdapter {
       return &MyPluginAdapter{
           Plugin: plugin,
           Options: options,
       }
   }
   
   // CreateComponent creates a custom plugin component
   func (a *MyPluginAdapter) CreateComponent(id, name, description string, parameters map[string]interface{}) (Component, error) {
       // Create execution function
       executeFunc := func(context *ExecutionContext) (*ExecutionResult, error) {
           // Implementation
           return &ExecutionResult{
               ComponentID: id,
               StepID:      context.StepID,
               Status:      "completed",
               Data:        map[string]interface{}{"result": "Custom plugin execution"},
               StartTime:   context.StartTime,
               EndTime:     time.Now(),
               Duration:    time.Since(context.StartTime),
               Metadata:    make(map[string]interface{}),
           }, nil
       }
       
       // Create component
       return NewComponentAdapter(id, name, description, "myplugin", executeFunc), nil
   }
   
   // Type returns the component type
   func (a *MyPluginAdapter) Type() string {
       return "myplugin"
   }
   ```

4. Register the adapter in the integration API:
   ```go
   // pkg/integration/api.go (modify existing function)
   
   // registerComponentAdapters registers component adapters
   func (a *IntegrationAPI) registerComponentAdapters() {
       // Existing adapters
       a.ComponentFactory.RegisterCreator(NewTimeTravelAdapter(nil, nil))
       a.ComponentFactory.RegisterCreator(NewPersonaAdapter(nil, nil))
       a.ComponentFactory.RegisterCreator(NewAdaptiveAdapter(nil, nil))
       a.ComponentFactory.RegisterCreator(NewScannerAdapter(nil, nil))
       
       // New adapter
       a.ComponentFactory.RegisterCreator(NewMyPluginAdapter(nil, nil))
   }
   ```

### Creating a New Template

Templates are defined in YAML format:

```yaml
# templates/custom-template.yaml
id: custom-template
info:
  name: Custom Vulnerability Template
  author: Your Name
  severity: medium
  description: Detects a custom vulnerability
  tags: custom, vulnerability

requests:
  - method: GET
    path: /vulnerable-endpoint
    matchers:
      - type: word
        words:
          - "vulnerable string"
        part: body
    extractors:
      - type: regex
        regex:
          - "sensitive data: (.*)"
        part: body
```

### Adding a New Protocol Handler

1. Create a new protocol handler in `pkg/core/protocol/`:
   ```go
   // pkg/core/protocol/custom.go
   package protocol

   import (
       "fmt"
   )

   // CustomProtocolHandler handles custom protocol
   type CustomProtocolHandler struct {
       // Handler configuration
       Config *CustomProtocolConfig
   }

   // CustomProtocolConfig contains handler configuration
   type CustomProtocolConfig struct {
       // Configuration fields
       Timeout int
       Options map[string]interface{}
   }

   // NewCustomProtocolHandler creates a new custom protocol handler
   func NewCustomProtocolHandler(config *CustomProtocolConfig) *CustomProtocolHandler {
       return &CustomProtocolHandler{
           Config: config,
       }
   }

   // Execute executes a request using the custom protocol
   func (h *CustomProtocolHandler) Execute(request *Request) (*Response, error) {
       // Protocol implementation
       return &Response{
           StatusCode: 200,
           Body:       []byte("Custom protocol response"),
           Headers:    map[string][]string{"Content-Type": {"text/plain"}},
       }, nil
   }
   ```

2. Register the protocol handler in the protocol registry:
   ```go
   // pkg/core/protocol/protocol.go (modify existing function)
   
   // RegisterProtocolHandlers registers protocol handlers
   func (r *ProtocolRegistry) RegisterProtocolHandlers() {
       // Existing handlers
       r.RegisterHandler("http", NewHTTPProtocolHandler(nil))
       r.RegisterHandler("https", NewHTTPProtocolHandler(nil))
       
       // New handler
       r.RegisterHandler("custom", NewCustomProtocolHandler(nil))
   }
   ```

## Testing

### Unit Testing

Write unit tests for your code:

```go
// pkg/myplugin/plugin_test.go
package myplugin

import (
    "testing"
)

func TestPlugin(t *testing.T) {
    // Create plugin
    config := &Config{
        Enabled: true,
        Options: map[string]interface{}{
            "option1": "value1",
        },
    }
    plugin := NewPlugin(config)
    
    // Test execution
    result, err := plugin.Execute("example.com")
    if err != nil {
        t.Fatalf("Failed to execute plugin: %v", err)
    }
    
    // Check result
    expected := "Executed plugin on example.com"
    if result != expected {
        t.Errorf("Expected %q, got %q", expected, result)
    }
}
```

### Integration Testing

Write integration tests to verify component interaction:

```go
// test/myplugin_test.go
package test

import (
    "testing"
)

func TestMyPluginIntegration(t *testing.T) {
    // Create logger
    logger := NewTestLogger()
    
    // Create integration API
    api := NewIntegrationAPI(logger)
    
    // Initialize API
    err := api.Initialize()
    if err != nil {
        t.Fatalf("Failed to initialize integration API: %v", err)
    }
    
    // Create scan options
    options := NewScanOptions()
    options.WorkflowID = "myplugin-workflow"
    
    // Perform scan
    result, err := api.Scan("example.com", options)
    if err != nil {
        t.Fatalf("Failed to perform scan: %v", err)
    }
    
    // Check scan result
    if result.Status != "completed" {
        t.Errorf("Expected status to be completed, got %s", result.Status)
    }
}
```

## Code Style and Guidelines

### Go Style Guide

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` to format your code
- Use `golint` and `go vet` to check for issues

### Commit Guidelines

- Use descriptive commit messages
- Follow the format: `type(scope): description`
- Types: feat, fix, docs, style, refactor, test, chore

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## Documentation

### Code Documentation

Document your code using Go's standard comment format:

```go
// FunctionName does something specific
// It takes a string parameter and returns an integer
// Example:
//
//     result := FunctionName("example")
//     fmt.Println(result)
//
func FunctionName(param string) int {
    // Implementation
    return 0
}
```

### API Documentation

Generate API documentation using `godoc`:

```bash
godoc -http=:6060
```

Then visit `http://localhost:6060/pkg/github.com/dejavu/scanner/`

## Release Process

1. Update version in `cmd/deja_vu/main.go`
2. Update CHANGELOG.md
3. Create a new tag:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```
4. Build release binaries:
   ```bash
   make release
   ```
5. Create a new release on GitHub with the built binaries

## Troubleshooting Development Issues

### Common Issues

1. **Import Cycle**: Ensure your package dependencies don't create cycles
2. **Build Errors**: Check for syntax errors and missing dependencies
3. **Test Failures**: Verify test expectations and mock objects

### Debugging

Use Go's built-in debugging tools:

```go
import "log"

// Debug output
log.Printf("Debug: %+v", someVariable)
```

For more advanced debugging, use Delve:

```bash
go get -u github.com/go-delve/delve/cmd/dlv
dlv debug ./cmd/deja_vu
```

## Community and Support

- GitHub Issues: Report bugs and request features
- Discussions: Ask questions and share ideas
- Slack: Join the community chat
- Mailing List: Subscribe for updates and announcements

## License

This project is licensed under the MIT License - see the LICENSE file for details.
