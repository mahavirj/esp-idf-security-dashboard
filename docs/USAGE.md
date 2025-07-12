# Usage Guide

This guide explains how to use the ESP-IDF Security Vulnerability Dashboard.

## 📊 Viewing the Dashboard

### Live Dashboard
Visit: **https://mahavirj.github.io/esp-idf-security-dashboard**

The dashboard provides:
- **Overview statistics** showing total vulnerabilities by severity
- **Version filtering** to focus on specific ESP-IDF releases
- **Severity filtering** to show only Critical, High, Medium, or Low severity issues
- **Search functionality** to find specific CVEs or components
- **Detailed vulnerability information** including fix versions

### Dashboard Features

#### Navigation
- **Stats Cards**: Top section shows totals for each severity level
- **Filters**: Use dropdowns and search to filter results
- **Release Cards**: Each ESP-IDF version shows summary and details
- **Export**: Download scan data as JSON for integration

#### Understanding Severity Levels
- **Critical**: Immediate action required, high risk of exploitation
- **High**: Should be addressed promptly, significant security risk
- **Medium**: Should be planned for remediation, moderate risk
- **Low**: Low priority, minimal security impact

## 🔧 Manual Scanning

### Prerequisites
```bash
# Install esp-idf-sbom tool
pip install esp-idf-sbom

# For Docker-based scanning (recommended)
docker --version

# For git-based scanning (fallback)
git --version
```

### Basic Usage

#### Scan Recent Stable Versions (Default)
```bash
python scan_releases.py --output-dir ./data
```

#### Scan Specific Versions
```bash
python scan_releases.py --versions v5.4.2,v5.3.3,v5.2.5 --output-dir ./data
```

#### Scan Single Version
```bash
python scan_releases.py --single-version v5.4.2 --output-dir ./data
```

#### Include Latest Branch Code
```bash
python scan_releases.py --versions v5.4.2 --include-branches master,release-v5.4 --output-dir ./data
```

#### Use Git Only (No Docker)
```bash
python scan_releases.py --no-docker --versions v5.4.2 --output-dir ./data
```

### Available Options

```bash
python scan_releases.py --help
```

| Option | Description |
|--------|-------------|
| `--output-dir DIR` | Directory to store scan results (default: ./data) |
| `--versions LIST` | Comma-separated list of versions to scan |
| `--single-version VER` | Scan only one version (for testing) |
| `--include-branches LIST` | Also scan latest code from specified branches |
| `--no-docker` | Disable Docker, use git clone only |
| `--list-docker-images` | Show available Docker images and exit |

### Scanning Methods

The scanner uses two methods in order of preference:

1. **Docker Images** (Primary)
   - Uses official ESP-IDF Docker images from `espressif/idf`
   - Faster and more reliable
   - Pre-configured environment
   - Available for all stable releases

2. **Git Clone** (Fallback)
   - Clones ESP-IDF repository and checks out specific version
   - Used when Docker image not available
   - Required for scanning latest branch code
   - Slower but more flexible

## 🤖 Automated Scanning

### GitHub Actions
The repository includes automated scanning via GitHub Actions:

#### Daily Scans
- Runs automatically at 00:00 UTC daily
- Scans recent versions of each major release series
- Updates the dashboard automatically
- Creates GitHub issues for high-severity vulnerabilities

#### Manual Triggers
You can trigger scans manually with custom parameters:

1. Go to **Actions** tab in GitHub repository
2. Select **"ESP-IDF Security Vulnerability Scan"** workflow
3. Click **"Run workflow"**
4. Configure options:
   - **Versions**: Specific versions to scan (optional)
   - **Force full scan**: Scan all supported versions
   - **ESP-IDF repository**: Custom repository URL (optional)

### Workflow Configuration

The workflow scans versions in parallel using a matrix strategy:
- `release-v5.0`: Latest v5.0.x versions
- `release-v5.1`: Latest v5.1.x versions  
- `release-v5.2`: Latest v5.2.x versions
- `release-v5.3`: Latest v5.3.x versions
- `release-v5.4`: Latest v5.4.x versions

## 📈 Interpreting Results

### For Product Developers

#### Version Selection
- **Compare releases**: See which versions have fewer vulnerabilities
- **Security trends**: Understand if newer versions fix security issues
- **LTS considerations**: Balance stability vs security for long-term support

#### Component Analysis
- **Third-party libraries**: Identify which components need updates
- **Impact assessment**: Check if vulnerabilities affect your specific usage
- **Fix planning**: Determine if issues can be resolved by component updates

#### Migration Planning
- **Upgrade benefits**: Quantify security improvements from version upgrades
- **Cherry-pick decisions**: Identify specific fixes that can be backported
- **Release timeline**: Plan security updates based on vulnerability severity

### For Security Teams

#### Risk Assessment
- **Severity distribution**: Understand overall security posture
- **Component inventory**: Track third-party dependencies
- **Trend analysis**: Monitor security improvements over time

#### Vulnerability Management
- **Prioritization**: Focus on Critical and High severity issues first
- **Remediation tracking**: Monitor progress on security fixes
- **Compliance reporting**: Generate reports for security audits

#### Incident Response
- **Active monitoring**: Watch for new Critical vulnerabilities
- **Impact analysis**: Quickly assess if new CVEs affect your products
- **Communication**: Use dashboard data for stakeholder updates

## 🔍 Data Format

### Scan Results Structure
```json
{
  "release_version": "v5.4.2",
  "scan_date": "2025-07-12T10:30:00Z",
  "tool_version": "0.20.1",
  "total_components": 45,
  "vulnerabilities": [
    {
      "cve_id": "CVE-2023-1234",
      "component": "openssl",
      "component_version": "1.1.1k", 
      "severity": "HIGH",
      "description": "Buffer overflow vulnerability...",
      "fixed_versions": ["1.1.1l", "3.0.1"],
      "affects_binary": true
    }
  ],
  "summary": {
    "total_vulnerabilities": 3,
    "by_severity": {
      "CRITICAL": 0,
      "HIGH": 1,
      "MEDIUM": 2,
      "LOW": 0
    }
  },
  "metadata": {
    "scanner": "esp-idf-security-dashboard",
    "scan_method": "docker",
    "docker_image": "espressif/idf:v5.4.2"
  }
}
```

### Key Fields
- **cve_id**: Common Vulnerabilities and Exposures identifier
- **component**: Affected third-party library/component
- **severity**: CVSS-based severity level
- **fixed_versions**: Component versions that fix the vulnerability
- **affects_binary**: Whether vulnerability affects compiled binary

## 🚨 Alerts and Notifications

### GitHub Issues
High and Critical severity vulnerabilities automatically create GitHub issues:
- **Automatic creation** for new high-severity findings
- **Updates** to existing issues with new scan results
- **Labels**: `security`, `vulnerability-scan`, `high-priority`
- **Details**: Links to dashboard and remediation guidance

### Custom Integrations
Use the JSON API to integrate with other tools:
- **CI/CD pipelines**: Fail builds on Critical vulnerabilities
- **Monitoring systems**: Alert on new security issues
- **Dashboards**: Create custom visualizations
- **Reports**: Generate security compliance reports

## 🔄 Troubleshooting

### Common Issues

#### Docker Not Available
```bash
# Use git-only mode
python scan_releases.py --no-docker --versions v5.4.2
```

#### Scan Failures
```bash
# Check tool installation
pip show esp-idf-sbom

# Verify Docker images
python scan_releases.py --list-docker-images

# Test single version
python scan_releases.py --single-version v5.4.2 --output-dir ./test
```

#### Permission Issues
```bash
# Ensure output directory is writable
mkdir -p data
chmod 755 data

# Check Docker permissions (Linux)
sudo usermod -aG docker $USER
```

### Debug Mode
Enable verbose logging:
```bash
# Add debug logging to scanner
export PYTHONPATH=.
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
exec(open('scan_releases.py').read())
" --single-version v5.4.2
```

## 🤝 Contributing

### Reporting Issues
- **Bug reports**: Use GitHub Issues with detailed reproduction steps
- **Feature requests**: Describe use case and expected behavior
- **Security issues**: Use GitHub Security Advisories for responsible disclosure

### Development
- **Fork** the repository
- **Create feature branch**: `git checkout -b feature/new-feature`
- **Test changes**: Verify with sample data
- **Submit PR**: Include description and test results