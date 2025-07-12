#!/usr/bin/env python3

"""
ESP-IDF Security Vulnerability Scanner

This script scans ESP-IDF releases for security vulnerabilities using:
1. ESP-IDF Docker images for stable releases (primary method)
2. Remote repository cloning for latest branch code (optional)

Uses esp-idf-sbom manifest check command for vulnerability detection.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ESP-IDF Docker image mappings for stable releases
ESP_IDF_DOCKER_IMAGES = {
    'v5.4.2': 'espressif/idf:v5.4.2',
    'v5.4.1': 'espressif/idf:v5.4.1', 
    'v5.3.3': 'espressif/idf:v5.3.3',
    'v5.3.2': 'espressif/idf:v5.3.2',
    'v5.3.1': 'espressif/idf:v5.3.1',
    'v5.2.5': 'espressif/idf:v5.2.5',
    'v5.2.4': 'espressif/idf:v5.2.4',
    'v5.2.3': 'espressif/idf:v5.2.3',
    'v5.2.2': 'espressif/idf:v5.2.2',
    'v5.2.1': 'espressif/idf:v5.2.1',
    'v5.1.6': 'espressif/idf:v5.1.6',
    'v5.1.5': 'espressif/idf:v5.1.5',
    'v5.1.4': 'espressif/idf:v5.1.4',
    'v5.1.3': 'espressif/idf:v5.1.3',
    'v5.1.2': 'espressif/idf:v5.1.2',
    'v5.1.1': 'espressif/idf:v5.1.1',
    'v5.0.9': 'espressif/idf:v5.0.9',
    'v5.0.8': 'espressif/idf:v5.0.8',
    'v5.0.7': 'espressif/idf:v5.0.7',
    'v5.0.6': 'espressif/idf:v5.0.6',
    'v5.0.5': 'espressif/idf:v5.0.5',
    'v5.0.4': 'espressif/idf:v5.0.4',
    'v5.0.3': 'espressif/idf:v5.0.3',
    'v5.0.2': 'espressif/idf:v5.0.2',
    'v5.0.1': 'espressif/idf:v5.0.1'
}

# Default releases to scan (most recent stable versions)
DEFAULT_RELEASES = [
    'v5.4.2', 'v5.4.1',
    'v5.3.3', 'v5.3.2', 
    'v5.2.5', 'v5.2.4',
    'v5.1.6', 'v5.1.5',
    'v5.0.9', 'v5.0.8'
]

class ESPIDFSecurityScanner:
    def __init__(self, output_dir, use_docker=True):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_docker = use_docker
        
        # Check Docker availability if using Docker
        if self.use_docker:
            self._check_docker()
        
    def _check_docker(self):
        """Check if Docker is available"""
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, check=True)
            logger.info(f"Docker available: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Docker is required but not available. Please install Docker or use --no-docker option.")
            
    def run_command(self, cmd, cwd=None, check=True, shell=True):
        """Run a command and return the result"""
        try:
            result = subprocess.run(
                cmd, shell=shell, cwd=cwd, 
                capture_output=True, text=True, check=check
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {cmd}")
            logger.error(f"Error: {e.stderr}")
            raise
            
    def scan_version_with_docker(self, version):
        """Scan ESP-IDF version using Docker image"""
        docker_image = ESP_IDF_DOCKER_IMAGES.get(version)
        if not docker_image:
            logger.error(f"No Docker image available for version {version}")
            return None
            
        logger.info(f"Scanning {version} using Docker image: {docker_image}")
        
        try:
            # Update NVD database (only once per run)
            if not hasattr(self, '_db_synced'):
                logger.info("Syncing NVD database...")
                try:
                    self.run_command("pip install -q esp-idf-sbom && esp-idf-sbom sync-db")
                    self._db_synced = True
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to sync NVD database: {e}")
                    self._db_synced = True
            
            # Create temporary container and scan
            container_name = f"esp-idf-scan-{version.replace('.', '-')}"
            
            # Pull the Docker image
            logger.info(f"Pulling Docker image: {docker_image}")
            self.run_command(f"docker pull {docker_image}")
            
            # Run vulnerability scan inside container
            docker_cmd = f"""
            docker run --rm --name {container_name} \
                -v /tmp:/tmp \
                {docker_image} \
                bash -c "
                    pip install -q esp-idf-sbom && \
                    esp-idf-sbom sync-db && \
                    esp-idf-sbom manifest check --format=json --local-db --no-sync-db /opt/esp/idf
                "
            """
            
            result = self.run_command(docker_cmd, check=False)
            
            if result.returncode not in [0, 1]:  # 0 = no vulns, 1 = vulns found
                logger.error(f"Docker scan failed for {version}: {result.stderr}")
                return None
                
            try:
                if result.stdout.strip():
                    scan_result = json.loads(result.stdout)
                else:
                    scan_result = {"vulnerabilities": []}
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse scan result for {version}: {e}")
                return None
                
            return scan_result
            
        except Exception as e:
            logger.error(f"Docker scan failed for {version}: {e}")
            return None
            
    def scan_version_with_git(self, version, repository_url="https://github.com/espressif/esp-idf.git"):
        """Scan ESP-IDF version by cloning from git repository"""
        logger.info(f"Scanning {version} by cloning from repository")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "esp-idf"
            
            try:
                # Clone repository
                logger.info(f"Cloning ESP-IDF repository...")
                self.run_command(f"git clone --depth 1 --branch {version} --recursive {repository_url} {repo_path}")
                
                # Update NVD database (only once per run)
                if not hasattr(self, '_db_synced'):
                    logger.info("Syncing NVD database...")
                    try:
                        self.run_command("esp-idf-sbom sync-db")
                        self._db_synced = True
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to sync NVD database: {e}")
                        self._db_synced = True
                
                # Run vulnerability scan
                result = self.run_command(
                    f"esp-idf-sbom manifest check --format=json --local-db --no-sync-db {repo_path}",
                    check=False
                )
                
                if result.returncode not in [0, 1]:
                    logger.error(f"Git scan failed for {version}: {result.stderr}")
                    return None
                    
                try:
                    if result.stdout.strip():
                        scan_result = json.loads(result.stdout)
                    else:
                        scan_result = {"vulnerabilities": []}
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse scan result for {version}: {e}")
                    return None
                    
                return scan_result
                
            except Exception as e:
                logger.error(f"Git scan failed for {version}: {e}")
                return None
                
    def scan_latest_branch(self, branch="master", repository_url="https://github.com/espressif/esp-idf.git"):
        """Scan latest code from a specific branch"""
        logger.info(f"Scanning latest code from branch: {branch}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "esp-idf"
            
            try:
                # Clone repository
                logger.info(f"Cloning ESP-IDF repository branch {branch}...")
                self.run_command(f"git clone --depth 1 --branch {branch} --recursive {repository_url} {repo_path}")
                
                # Get commit info for version identifier
                commit_result = self.run_command("git rev-parse --short HEAD", cwd=repo_path)
                commit_hash = commit_result.stdout.strip()
                
                date_result = self.run_command("git log -1 --format=%ci", cwd=repo_path)
                commit_date = date_result.stdout.strip()
                
                version_id = f"{branch}-{commit_hash}"
                
                # Update NVD database (only once per run)
                if not hasattr(self, '_db_synced'):
                    logger.info("Syncing NVD database...")
                    try:
                        self.run_command("esp-idf-sbom sync-db")
                        self._db_synced = True
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to sync NVD database: {e}")
                        self._db_synced = True
                
                # Run vulnerability scan
                result = self.run_command(
                    f"esp-idf-sbom manifest check --format=json --local-db --no-sync-db {repo_path}",
                    check=False
                )
                
                if result.returncode not in [0, 1]:
                    logger.error(f"Branch scan failed for {branch}: {result.stderr}")
                    return None, None
                    
                try:
                    if result.stdout.strip():
                        scan_result = json.loads(result.stdout)
                    else:
                        scan_result = {"vulnerabilities": []}
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse scan result for {branch}: {e}")
                    return None, None
                    
                return version_id, scan_result
                
            except Exception as e:
                logger.error(f"Branch scan failed for {branch}: {e}")
                return None, None
                
    def parse_and_store_results(self, scan_result, version, tool_version, scan_method="docker"):
        """Parse scan results and store in dashboard format"""
        vulnerabilities = scan_result.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity in severity_count:
                severity_count[severity] += 1
                
        # Create dashboard data structure
        dashboard_data = {
            "release_version": version,
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "tool_version": tool_version,
            "total_components": len(scan_result.get("components", scan_result.get("packages", []))),
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "by_severity": severity_count
            },
            "metadata": {
                "scanner": "esp-idf-security-dashboard",
                "scan_method": scan_method,
                "docker_image": ESP_IDF_DOCKER_IMAGES.get(version) if scan_method == "docker" else None
            }
        }
        
        # Save to output directory
        output_file = self.output_dir / f"{version}.json"
        with open(output_file, 'w') as f:
            json.dump(dashboard_data, f, indent=2)
            
        logger.info(f"Saved scan results for {version} to {output_file}")
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities: {severity_count}")
        return dashboard_data
        
    def get_tool_version(self):
        """Get esp-idf-sbom tool version"""
        try:
            result = self.run_command("pip show esp-idf-sbom")
            for line in result.stdout.split('\n'):
                if line.startswith('Version:'):
                    return line.split(':', 1)[1].strip()
        except:
            pass
        return "unknown"
        
    def scan_version(self, version):
        """Scan a single ESP-IDF version using the best available method"""
        logger.info(f"Starting scan for {version}")
        
        scan_result = None
        scan_method = None
        
        # Try Docker first if available and image exists
        if self.use_docker and version in ESP_IDF_DOCKER_IMAGES:
            scan_result = self.scan_version_with_docker(version)
            scan_method = "docker"
            
        # Fall back to git clone if Docker failed or not available
        if scan_result is None:
            logger.info(f"Falling back to git clone for {version}")
            scan_result = self.scan_version_with_git(version)
            scan_method = "git"
            
        if scan_result is None:
            logger.error(f"Failed to scan {version} with any method")
            return None
            
        # Parse and store results
        tool_version = self.get_tool_version()
        dashboard_data = self.parse_and_store_results(scan_result, version, tool_version, scan_method)
        
        return dashboard_data
        
    def scan_releases(self, releases, include_branches=None):
        """Scan multiple ESP-IDF releases and optionally latest branches"""
        results = {}
        
        # Scan specified releases
        logger.info(f"Scanning {len(releases)} releases: {releases}")
        
        for version in releases:
            logger.info(f"Processing {version}")
            result = self.scan_version(version)
            if result:
                results[version] = result
                logger.info(f"✅ Successfully scanned {version}")
            else:
                logger.error(f"❌ Failed to scan {version}")
                
        # Scan latest branches if requested
        if include_branches:
            logger.info(f"Scanning latest code from branches: {include_branches}")
            for branch in include_branches:
                version_id, scan_result = self.scan_latest_branch(branch)
                if scan_result:
                    tool_version = self.get_tool_version()
                    dashboard_data = self.parse_and_store_results(scan_result, version_id, tool_version, "git-branch")
                    results[version_id] = dashboard_data
                    logger.info(f"✅ Successfully scanned branch {branch} as {version_id}")
                else:
                    logger.error(f"❌ Failed to scan branch {branch}")
                    
        # Create summary file
        summary = {
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "scanned_versions": list(results.keys()),
            "total_scanned": len(results),
            "scanner_info": {
                "tool": "esp-idf-security-dashboard",
                "methods": ["docker", "git"] if self.use_docker else ["git"],
                "esp_idf_sbom_version": self.get_tool_version()
            }
        }
        
        summary_file = self.output_dir / "scan_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        logger.info(f"Scan complete. Results saved to {self.output_dir}")
        logger.info(f"Successfully scanned: {len(results)} items")
        return results

def main():
    parser = argparse.ArgumentParser(description="Scan ESP-IDF releases for security vulnerabilities")
    parser.add_argument("--output-dir", default="./data", 
                       help="Directory to store scan results")
    parser.add_argument("--versions", 
                       help="Comma-separated list of versions to scan (default: recent stable versions)")
    parser.add_argument("--single-version", 
                       help="Scan a single version (for testing)")
    parser.add_argument("--include-branches",
                       help="Comma-separated list of branches to scan (e.g., master,release-v5.4)")
    parser.add_argument("--no-docker", action="store_true",
                       help="Disable Docker and use git clone only")
    parser.add_argument("--list-docker-images", action="store_true",
                       help="List available Docker images and exit")
    
    args = parser.parse_args()
    
    if args.list_docker_images:
        print("Available ESP-IDF Docker images:")
        for version, image in ESP_IDF_DOCKER_IMAGES.items():
            print(f"  {version}: {image}")
        print(f"\nTotal: {len(ESP_IDF_DOCKER_IMAGES)} images")
        return
    
    try:
        scanner = ESPIDFSecurityScanner(args.output_dir, use_docker=not args.no_docker)
        
        if args.single_version:
            versions = [args.single_version]
        elif args.versions:
            versions = [v.strip() for v in args.versions.split(',')]
        else:
            versions = DEFAULT_RELEASES
            
        branches = None
        if args.include_branches:
            branches = [b.strip() for b in args.include_branches.split(',')]
            
        logger.info(f"ESP-IDF Security Scanner starting...")
        logger.info(f"Output directory: {args.output_dir}")
        logger.info(f"Using Docker: {not args.no_docker}")
        logger.info(f"Versions to scan: {len(versions)}")
        if branches:
            logger.info(f"Branches to scan: {branches}")
        
        results = scanner.scan_releases(versions, include_branches=branches)
        
        if results:
            print(f"\n✅ Successfully scanned {len(results)} items")
            
            # Print summary
            total_vulns = sum(r["summary"]["total_vulnerabilities"] for r in results.values())
            print(f"📊 Total vulnerabilities found: {total_vulns}")
            
            # Print severity breakdown
            severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for result in results.values():
                for severity, count in result["summary"]["by_severity"].items():
                    severity_totals[severity] += count
                    
            print("📋 Severity breakdown:")
            for severity, count in severity_totals.items():
                if count > 0:
                    print(f"   {severity}: {count}")
                    
        else:
            print("❌ No items were successfully scanned")
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"❌ Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()