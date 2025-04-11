# Deja Vu Architecture Design

## Overview

Deja Vu is designed as a modular, extensible vulnerability scanner that builds upon Nuclei's foundation while incorporating advanced features from the evolution roadmap. The architecture follows a plugin-based approach to ensure flexibility, maintainability, and the ability to enable/disable features independently.

## System Architecture

### High-Level Architecture Diagram

```
+---------------------+
|    CLI Interface    |
+----------+----------+
           |
+----------v----------+
|    Core Engine      |
+---------------------+
|  Template Processor |
|  Target Manager     |
|  Execution Engine   |
|  Result Processor   |
+----------+----------+
           |
+----------v----------+
|  Feature Modules    |
+---------------------+
|  Time Travel        |
|  Persona Engine     |
|  Adaptive Learning  |
|  (Future Modules)   |
+----------+----------+
           |
+----------v----------+
|  External Services  |
+---------------------+
|  Wayback Machine    |
|  Certificate DBs    |
|  ML Services        |
+---------------------+
```

## Component Descriptions

### 1. Core Engine

The Core Engine is responsible for the fundamental scanning functionality, building upon Nuclei's proven architecture.

#### 1.1 Template Processor
- Parses and validates YAML templates
- Supports Nuclei's existing template format
- Extends template capabilities for advanced features
- Implements template clustering for optimization

#### 1.2 Target Manager
- Handles target input (URLs, IPs, domains)
- Manages target enrichment from various sources
- Implements target filtering and prioritization
- Coordinates with Time Travel module for historical targets

#### 1.3 Execution Engine
- Orchestrates the scanning process
- Manages concurrency and rate limiting
- Implements protocol handlers (HTTP, DNS, TCP, etc.)
- Provides hooks for feature modules to modify execution

#### 1.4 Result Processor
- Collects and processes scan results
- Formats output in various formats (JSON, YAML, etc.)
- Implements deduplication and filtering
- Provides feedback to Adaptive Learning module

### 2. Feature Modules

Feature modules extend the core functionality with advanced capabilities, implemented as plugins that can be enabled or disabled.

#### 2.1 Time Travel Module
- Interfaces with historical data sources (Wayback Machine, etc.)
- Retrieves and processes historical URLs and configurations
- Filters and prioritizes historical assets
- Integrates with Target Manager to expand scan scope

```go
// TimeTravel module interface
type TimeTravelModule interface {
    EnrichWithHistory(target string) []string
    GetHistoricalConfigurations(target string) map[string]interface{}
    FilterRelevantAssets(assets []string) []string
}
```

#### 2.2 Persona Engine
- Manages attacker personas and their attributes
- Modifies request patterns based on persona profiles
- Implements variable delays and rate limiting
- Prioritizes templates based on persona preferences

```go
// Persona module interface
type PersonaModule interface {
    LoadPersona(name string) error
    ModifyRequest(req *Request) *Request
    GetScanningPattern() ScanPattern
    GetTemplatePriorities() []string
}
```

#### 2.3 Adaptive Learning Engine
- Detects target technology stack
- Prioritizes templates based on target characteristics
- Collects feedback on scan effectiveness
- Provides foundation for future ML integration

```go
// AdaptiveLearning module interface
type AdaptiveLearningModule interface {
    DetectTechStack(target string) *TechStack
    PrioritizeTemplates(templates []string, techStack *TechStack) []string
    RecordFeedback(template string, result ScanResult)
}
```

### 3. Plugin System

The Plugin System enables the dynamic loading and management of feature modules.

#### 3.1 Plugin Manager
- Discovers and loads plugins at runtime
- Manages plugin lifecycle (init, start, stop)
- Handles plugin dependencies and conflicts
- Provides configuration interface for plugins

#### 3.2 Plugin Interface
- Standardized interface for all plugins
- Event hooks for various scanning phases
- Configuration management
- Resource allocation and cleanup

```go
// Plugin interface
type Plugin interface {
    Name() string
    Version() string
    Initialize(config map[string]interface{}) error
    Start() error
    Stop() error
    Hooks() map[string]interface{}
}
```

### 4. Configuration System

The Configuration System manages user preferences and feature settings.

#### 4.1 Configuration Manager
- Parses command-line arguments
- Loads configuration from files
- Validates and normalizes settings
- Distributes configuration to components

#### 4.2 Feature Flags
- Enables/disables features
- Controls feature behavior
- Manages feature interactions
- Provides defaults for missing settings

## Data Flow

### Scanning Process

1. User provides targets and options via CLI
2. Configuration Manager processes options and loads appropriate plugins
3. Target Manager processes input targets
4. Time Travel Module enriches targets with historical data (if enabled)
5. Template Processor loads and prepares templates
6. Adaptive Learning Engine prioritizes templates based on target (if enabled)
7. Persona Engine configures scanning behavior (if enabled)
8. Execution Engine performs the scan with modified behavior
9. Result Processor collects and formats results
10. Adaptive Learning Engine records feedback for future scans

### Plugin Interaction

Plugins interact with the core engine through well-defined hooks:

- `pre_scan`: Called before scanning begins
- `post_target_load`: Called after targets are loaded
- `pre_template_execution`: Called before each template is executed
- `post_template_execution`: Called after each template is executed
- `post_scan`: Called after scanning completes

## Technology Stack

### Core Components
- **Language**: Go (1.18+)
- **Configuration**: YAML
- **Template Format**: Extended Nuclei YAML format

### Feature-Specific Technologies
- **Time Travel**: Go HTTP clients, Archive.org API, Censys API
- **Persona Engine**: Go with YAML configuration
- **Adaptive Learning**: Go with optional Python bridge for ML

### External Dependencies
- **Nuclei Core**: Fork of Nuclei's core components
- **HTTP Libraries**: net/http, fasthttp
- **YAML Processing**: gopkg.in/yaml.v3
- **Concurrency**: Go routines and channels

## Deployment Architecture

### Local Deployment
- Single binary with embedded plugins
- Configuration files for features
- Local template repository

### Future Considerations
- Microservices for ML components
- Distributed scanning architecture
- Cloud-based template repository

## Security Considerations

### Ethical Scanning
- Rate limiting enforcement
- Target validation
- Responsible disclosure features

### Plugin Security
- Plugin signature verification
- Sandboxed execution
- Resource limitations

## Extensibility

The architecture is designed to accommodate future features:

- **Self-Healing Templates**: Will extend Template Processor
- **Advanced Evasion**: Will integrate with Execution Engine
- **Swarm Intelligence**: Will extend Template Processor and add distributed components
- **Autonomous Exploit Simulation**: Will add new plugin type with containerization

## Implementation Phases

### Phase 1: Foundation
- Core Engine implementation
- Plugin System
- Configuration System
- Basic CLI

### Phase 2: Initial Features
- Time Travel Module
- Persona Engine
- Simplified Adaptive Learning

### Phase 3: Advanced Features
- Enhanced ML capabilities
- Self-healing templates foundation
- Basic evasion techniques

### Phase 4: Future Expansion
- Distributed architecture
- Advanced AI components
- Blockchain integration foundation
