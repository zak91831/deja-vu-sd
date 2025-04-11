# Installation Guide

This guide provides detailed instructions for installing and configuring the Deja Vu vulnerability scanner.

## System Requirements

- **Operating System**: Linux, macOS, or Windows
- **CPU**: 2+ cores recommended
- **Memory**: 4GB RAM minimum, 8GB+ recommended
- **Disk Space**: 1GB for installation, additional space for scan results
- **Go**: Version 1.18 or higher
- **Network**: Internet connection for updates and certain scanning features

## Installation Methods

### Method 1: Pre-built Binaries

1. Download the latest release from the [releases page](https://github.com/dejavu/scanner/releases)
2. Extract the archive:
   ```bash
   tar -xzf dejavu-v1.0.0-linux-amd64.tar.gz
   ```
3. Move the binary to a location in your PATH:
   ```bash
   sudo mv dejavu /usr/local/bin/
   ```
4. Verify the installation:
   ```bash
   dejavu -version
   ```

### Method 2: Building from Source

1. Ensure Go 1.18+ is installed:
   ```bash
   go version
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/dejavu/scanner.git
   ```

3. Change to the project directory:
   ```bash
   cd scanner
   ```

4. Install dependencies:
   ```bash
   go mod download
   ```

5. Build the project:
   ```bash
   go build -o dejavu ./cmd/deja_vu
   ```

6. Move the binary to a location in your PATH (optional):
   ```bash
   sudo mv dejavu /usr/local/bin/
   ```

### Method 3: Docker

1. Pull the Docker image:
   ```bash
   docker pull dejavu/scanner:latest
   ```

2. Run the scanner:
   ```bash
   docker run -it dejavu/scanner -target example.com
   ```

## Configuration

### Configuration File

Deja Vu can be configured using a YAML configuration file. Create a file named `config.yaml` with the following structure:

```yaml
# Target configuration
target: example.com
targets_file: /path/to/targets.txt

# Workflow configuration
workflow: comprehensive-scan

# Output configuration
output: dejavu-results.json
output_format: json  # Options: json, xml, html, csv

# Performance configuration
threads: 10
timeout: 30
retries: 3

# Feature configuration
features:
  timetravel:
    enabled: true
    start_date: "2022-01-01"
    end_date: "2023-01-01"
  persona:
    enabled: true
    type: stealthy  # Options: standard, stealthy, aggressive, apt
  adaptive:
    enabled: true
    learning_rate: 0.1

# Proxy configuration
proxy: http://proxy.example.com:8080
proxy_auth: username:password

# Authentication configuration
auth:
  type: basic  # Options: basic, bearer, digest, oauth
  username: user
  password: pass
```

### Environment Variables

Deja Vu also supports configuration through environment variables:

```bash
# Set target
export DEJAVU_TARGET=example.com

# Set workflow
export DEJAVU_WORKFLOW=comprehensive-scan

# Set output file
export DEJAVU_OUTPUT=dejavu-results.json

# Set threads
export DEJAVU_THREADS=10
```

## Template Directory

Deja Vu looks for templates in the following locations:

1. The directory specified by the `-templates` flag
2. The directory specified by the `DEJAVU_TEMPLATES` environment variable
3. The `templates` directory in the current working directory
4. The `~/.dejavu/templates` directory

## Updating

### Updating Binary

To update a pre-built binary installation:

1. Download the latest release
2. Replace the existing binary

### Updating Source Installation

To update a source installation:

1. Pull the latest changes:
   ```bash
   git pull
   ```

2. Rebuild the project:
   ```bash
   go build -o dejavu ./cmd/deja_vu
   ```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the binary has execute permissions:
   ```bash
   chmod +x dejavu
   ```

2. **Templates Not Found**: Verify template directory location:
   ```bash
   dejavu -list-templates
   ```

3. **Network Issues**: Check proxy settings and connectivity:
   ```bash
   dejavu -debug -target example.com
   ```

### Logs

Logs are stored in the following locations:

- Linux/macOS: `~/.dejavu/logs/`
- Windows: `%USERPROFILE%\.dejavu\logs\`

### Getting Help

For additional help:

```bash
dejavu -help
```

For detailed documentation, visit the [official documentation](https://docs.dejavu-scanner.io).
