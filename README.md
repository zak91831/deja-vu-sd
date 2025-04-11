# Deja Vu: Next-Generation Adaptive Vulnerability Scanner

Deja Vu is a next-generation vulnerability scanner that evolves Nuclei's capabilities with advanced features including time-travel scanning, personality-driven scanning, and adaptive learning.

## Features

### Core Capabilities
- **Enhanced HTTP Interaction Model**: Advanced cookies, redirects, custom headers, session management, and authentication mechanisms
- **Improved Matcher System**: DSL for complex conditions, binary data matching, fuzzy matching, and multi-step validation logic
- **Expanded Protocol Support**: WebSocket, GraphQL, and modern framework-specific handlers
- **Advanced Extractor Engine**: JSON/XML path support, advanced regex capabilities, and correlation between extractions

### Advanced Features
- **Time-Travel Scanning**: Enriches targets with historical data from Wayback Machine and certificate transparency logs to identify vulnerabilities in past versions of websites
- **Personality-Driven Scanning**: Emulates different attacker personas (standard, stealthy, aggressive, APT) with customizable behaviors, headers, and rate limiting
- **Adaptive Learning Engine**: Detects target technology stacks and prioritizes templates accordingly, with feedback collection to improve future scans

### Integration Capabilities
- **Component Registry**: Centralized registry for all scanner components
- **Workflow Registry**: Organization of scanning workflows
- **Unified API**: Simple interface for executing scans with any workflow

## Installation

```bash
# Clone the repository
git clone https://github.com/dejavu/scanner.git

# Change to the project directory
cd scanner

# Build the project
go build -o dejavu ./cmd/deja_vu

# Run the scanner
./dejavu -target example.com
```

## Usage

### Basic Scanning

```bash
# Standard scan
./dejavu -target example.com

# Scan with specific template
./dejavu -target example.com -template sqli
```

### Advanced Features

```bash
# Time-travel scanning
./dejavu -target example.com -workflow timetravel-scan

# Personality-driven scanning
./dejavu -target example.com -workflow persona-stealthy-scan

# Adaptive learning scanning
./dejavu -target example.com -workflow adaptive-scan

# Comprehensive scanning (all features)
./dejavu -target example.com -workflow comprehensive-scan
```

### Configuration

Deja Vu can be configured using a YAML configuration file:

```bash
./dejavu -config config.yaml
```

Example configuration:

```yaml
target: example.com
workflow: comprehensive-scan
output: dejavu-results.json
threads: 10
timeout: 30
```

## Architecture

Deja Vu follows a modular, plugin-based architecture that allows features to be enabled/disabled independently while maintaining compatibility with existing Nuclei templates.

- **Core Engine**: Handles scanning operations, template execution, and result processing
- **Plugin System**: Provides extensibility for advanced features
- **Integration Layer**: Connects all components through a unified API

## Development

### Prerequisites

- Go 1.18 or higher
- Git

### Building from Source

```bash
# Clone the repository
git clone https://github.com/dejavu/scanner.git

# Change to the project directory
cd scanner

# Install dependencies
go mod download

# Build the project
go build -o dejavu ./cmd/deja_vu
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run specific tests
go test ./test/integration_test.go
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on the Nuclei vulnerability scanner
- Inspired by the vision of evolving vulnerability scanning with adaptive capabilities
