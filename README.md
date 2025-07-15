# ESP-IDF Security Vulnerability Dashboard

A comprehensive security vulnerability dashboard for ESP-IDF releases that tracks and displays security issues across different versions to help developers make informed decisions about updates and security patches.

## 🎯 Overview

This dashboard provides:
- **Automated vulnerability scanning** of ESP-IDF releases using `esp-idf-sbom`
- **Interactive web dashboard** with filtering and search capabilities
- **Daily automated updates** via GitHub Actions
- **Developer-friendly insights** for migration and security decisions

## 🌐 Live Dashboard

Visit the live dashboard at: **https://mahavirj.github.io/esp-idf-security-dashboard**

## 📊 Features

### Dashboard Features
- **Multi-version comparison** across ESP-IDF v5.0-v5.4 releases
- **Severity-based filtering** (Critical, High, Medium, Low)
- **Component analysis** showing affected third-party libraries
- **Search functionality** for CVE IDs and components
- **Export capabilities** for CI/CD integration
- **Mobile-responsive design**

### Automation Features
- **Daily vulnerability scans** using latest NVD database
- **GitHub Issues integration** for high-severity vulnerabilities
- **Matrix scanning** for parallel processing of multiple versions
- **Artifact storage** for historical scan data

## 🚀 Quick Start

### View the Dashboard
Simply visit the [live dashboard](https://mahavirj.github.io/esp-idf-security-dashboard) to see the latest vulnerability information.

### Manual Scanning
```bash
# Clone the repository
git clone https://github.com/mahavirj/esp-idf-security-dashboard.git
cd esp-idf-security-dashboard

# Install dependencies
pip install esp-idf-sbom

# Run a scan (requires ESP-IDF repository)
python scan_releases.py --esp-idf-path /path/to/esp-idf --output-dir data/ --versions v5.4.2
```

### Local Development
```bash
# Serve the dashboard locally
python -m http.server 8000

# Visit http://localhost:8000
```

## 📁 Repository Structure

```
esp-idf-security-dashboard/
├── README.md                 # This file
├── index.html               # Main dashboard interface
├── scan_releases.py         # Vulnerability scanning script
├── .github/
│   └── workflows/
│       └── security-scan.yml # Automated scanning workflow
├── data/                    # Real scan results (generated)
├── sample_data/             # Sample data for demonstration
└── docs/                    # Additional documentation
```

## 🔧 Configuration

### Environment Variables
- `ESP_IDF_REPOSITORY`: URL of ESP-IDF repository (default: https://github.com/espressif/esp-idf.git)
- `SCAN_VERSIONS`: Comma-separated list of versions to scan
- `OUTPUT_FORMAT`: Output format for scan results (json, csv, markdown)

### Supported ESP-IDF Versions
- **v5.4.x**: Latest stable series
- **v5.3.x**: Previous stable series  
- **v5.2.x**: LTS series
- **v5.1.x**: Previous LTS series
- **v5.0.x**: Legacy stable series

## 🛠 How It Works

### 1. Data Collection
- Uses `esp-idf-sbom manifest check` to scan ESP-IDF repository directly
- Syncs with National Vulnerability Database (NVD) for latest CVE information
- Processes manifest files and submodules for comprehensive analysis

### 2. Analysis
- Identifies vulnerable components across ESP-IDF versions
- Categorizes vulnerabilities by severity (CVSS scores)
- Tracks component versions and available fixes

### 3. Visualization
- Generates interactive web dashboard
- Provides filtering and search capabilities
- Shows trends and comparisons across versions

## 📈 Dashboard Usage

### For Product Developers
- **Compare versions**: See which ESP-IDF releases have fewer vulnerabilities
- **Component analysis**: Identify which third-party components need updates
- **Migration planning**: Understand security benefits of upgrading
- **Cherry-pick decisions**: Determine if specific fixes can be backported

### For Security Teams
- **Vulnerability tracking**: Monitor new CVEs affecting ESP-IDF
- **Risk assessment**: Evaluate impact of vulnerabilities on products
- **Patch management**: Plan security updates and releases
- **Compliance reporting**: Generate security reports for audits

## 🔄 Automation

### GitHub Actions Workflow
The repository includes a GitHub Actions workflow that:
- Runs daily at 00:00 UTC
- Scans multiple ESP-IDF versions in parallel
- Updates the dashboard automatically
- Creates GitHub issues for high-severity vulnerabilities
- Deploys updates to GitHub Pages

### Manual Triggers
You can manually trigger scans with custom parameters:
- Specific version lists
- Force full scans of all supported versions
- On-demand security audits

## 📊 Data Format

Scan results are stored in JSON format:

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
      "description": "Buffer overflow in OpenSSL...",
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
  }
}
```
