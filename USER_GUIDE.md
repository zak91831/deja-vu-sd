# User Guide

This guide provides detailed instructions for using the Deja Vu vulnerability scanner effectively.

## Getting Started

### Basic Scanning

To perform a basic scan against a target:

```bash
dejavu -target example.com
```

This will run a standard vulnerability scan using default templates.

### Specifying Output

To save scan results to a file:

```bash
dejavu -target example.com -output results.json
```

Available output formats:
- JSON (default): `-output-format json`
- XML: `-output-format xml`
- HTML: `-output-format html`
- CSV: `-output-format csv`

Example:
```bash
dejavu -target example.com -output results.html -output-format html
```

### Using Templates

To scan with specific templates:

```bash
dejavu -target example.com -template sqli,xss,ssrf
```

To scan with templates from a directory:

```bash
dejavu -target example.com -templates-dir /path/to/templates
```

## Advanced Features

### Time-Travel Scanning

Time-travel scanning allows you to scan historical versions of websites to identify vulnerabilities that may have existed in the past.

```bash
dejavu -target example.com -workflow timetravel-scan
```

With custom date range:

```bash
dejavu -target example.com -workflow timetravel-scan -start-date 2022-01-01 -end-date 2023-01-01
```

### Personality-Driven Scanning

Personality-driven scanning emulates different attacker personas with customized behaviors.

Available personas:
- Standard: Balanced approach
- Stealthy: Focuses on evasion and minimal footprint
- Aggressive: Maximum coverage with less concern for detection
- APT: Advanced Persistent Threat simulation

```bash
dejavu -target example.com -workflow persona-stealthy-scan
```

Custom persona configuration:

```bash
dejavu -target example.com -workflow persona-custom-scan -persona-config persona.yaml
```

### Adaptive Learning

Adaptive learning detects the target's technology stack and prioritizes templates accordingly.

```bash
dejavu -target example.com -workflow adaptive-scan
```

With custom learning parameters:

```bash
dejavu -target example.com -workflow adaptive-scan -learning-rate 0.2 -feedback true
```

### Comprehensive Scanning

Comprehensive scanning combines all advanced features for maximum coverage.

```bash
dejavu -target example.com -workflow comprehensive-scan
```

## Workflow Management

### Listing Available Workflows

To list all available scanning workflows:

```bash
dejavu -list-workflows
```

### Creating Custom Workflows

Custom workflows can be defined in YAML format:

```yaml
# custom-workflow.yaml
id: custom-workflow
name: Custom Workflow
description: Custom scanning workflow
steps:
  - id: adaptive
    name: Adaptive Scan
    description: Perform adaptive vulnerability scan
    component: adaptive
    parameters:
      templates: [default, custom]
  
  - id: timetravel
    name: Time Travel Scan
    description: Perform historical vulnerability scan
    component: time_travel
    parameters:
      start_date: 2022-01-01
      end_date: 2023-01-01
  
  - id: scan
    name: Standard Scan
    description: Perform standard vulnerability scan
    component: scanner
    parameters:
      templates: [default, custom]
```

To use a custom workflow:

```bash
dejavu -target example.com -workflow-file custom-workflow.yaml
```

## Performance Tuning

### Concurrency

Control the number of concurrent scans:

```bash
dejavu -target example.com -threads 10
```

### Timeouts

Set request timeout:

```bash
dejavu -target example.com -timeout 30
```

### Rate Limiting

Limit requests per second:

```bash
dejavu -target example.com -rate-limit 10
```

## Authentication

### Basic Authentication

```bash
dejavu -target example.com -auth-type basic -auth-user username -auth-pass password
```

### Bearer Token

```bash
dejavu -target example.com -auth-type bearer -auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Cookie Authentication

```bash
dejavu -target example.com -auth-type cookie -auth-cookie "session=abc123"
```

## Proxy Support

### HTTP Proxy

```bash
dejavu -target example.com -proxy http://proxy.example.com:8080
```

### SOCKS Proxy

```bash
dejavu -target example.com -proxy socks5://proxy.example.com:1080
```

### Authenticated Proxy

```bash
dejavu -target example.com -proxy http://user:pass@proxy.example.com:8080
```

## Reporting

### Vulnerability Reporting

Generate a comprehensive vulnerability report:

```bash
dejavu -target example.com -report-file report.pdf -report-format pdf
```

Available report formats:
- PDF
- HTML
- JSON
- XML
- CSV

### Severity Filtering

Filter results by severity:

```bash
dejavu -target example.com -severity high,critical
```

### Confidence Filtering

Filter results by confidence level:

```bash
dejavu -target example.com -min-confidence 0.7
```

## Continuous Integration

### CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install Deja Vu
      run: |
        curl -L https://github.com/dejavu/scanner/releases/download/v1.0.0/dejavu-v1.0.0-linux-amd64.tar.gz | tar xz
        sudo mv dejavu /usr/local/bin/
    - name: Run Scan
      run: |
        dejavu -target ${{ github.event.repository.homepage }} -output scan-results.json
    - name: Upload Results
      uses: actions/upload-artifact@v2
      with:
        name: scan-results
        path: scan-results.json
```

## Best Practices

1. **Start with Standard Scan**: Begin with a standard scan before using advanced features
2. **Use Appropriate Persona**: Choose the persona that matches your testing requirements
3. **Validate Findings**: Always validate findings to eliminate false positives
4. **Regular Scanning**: Implement regular scanning as part of your security program
5. **Template Updates**: Keep templates updated for the latest vulnerability coverage
6. **Rate Limiting**: Use appropriate rate limiting to avoid overwhelming target systems
7. **Legal Authorization**: Always ensure you have proper authorization before scanning

## Troubleshooting

### Debug Mode

Enable debug output for troubleshooting:

```bash
dejavu -target example.com -debug
```

### Verbose Mode

Enable verbose output for detailed information:

```bash
dejavu -target example.com -verbose
```

### Silent Mode

Disable all output except results:

```bash
dejavu -target example.com -silent
```

## Additional Resources

- [Official Documentation](https://docs.dejavu-scanner.io)
- [Template Writing Guide](https://docs.dejavu-scanner.io/templates)
- [API Reference](https://docs.dejavu-scanner.io/api)
- [Community Forum](https://community.dejavu-scanner.io)
