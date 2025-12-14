"""
CI/CD Integration Module
GitHub Actions, GitLab CI, SARIF output for security scanning
"""

import json
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class SARIFFinding:
    """SARIF format security finding"""
    rule_id: str
    level: str  # error, warning, note
    message: str
    location_uri: str
    location_line: int
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


class CICDIntegration:
    """CI/CD pipeline integration for security scanning"""
    
    SEVERITY_TO_SARIF = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'note'
    }
    
    def __init__(self):
        self.findings: List[SARIFFinding] = []
    
    def generate_sarif(self, scan_results: Dict[str, Any], tool_name: str = "Scorpion") -> Dict[str, Any]:
        """
        Generate SARIF format output for GitHub Security tab
        https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
        """
        
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": "2.0.0",
                            "informationUri": "https://github.com/Prince12sam/Scorpion",
                            "rules": []
                        }
                    },
                    "results": [],
                    "columnKind": "utf16CodeUnits"
                }
            ]
        }
        
        # Convert findings to SARIF format
        findings = scan_results.get('findings', [])
        rules_seen = set()
        
        for finding in findings:
            rule_id = finding.get('cwe_id', 'SCORPION-001')
            
            # Add rule if not seen
            if rule_id not in rules_seen:
                sarif['runs'][0]['tool']['driver']['rules'].append({
                    "id": rule_id,
                    "name": finding.get('category', 'SecurityVulnerability'),
                    "shortDescription": {
                        "text": finding.get('vulnerability', finding.get('description', 'Security issue detected'))
                    },
                    "fullDescription": {
                        "text": finding.get('remediation', 'Review and remediate this security issue')
                    },
                    "defaultConfiguration": {
                        "level": self.SEVERITY_TO_SARIF.get(finding.get('severity', 'medium'), 'warning')
                    },
                    "properties": {
                        "security-severity": str(finding.get('cvss_score', 5.0))
                    }
                })
                rules_seen.add(rule_id)
            
            # Add result
            sarif['runs'][0]['results'].append({
                "ruleId": rule_id,
                "level": self.SEVERITY_TO_SARIF.get(finding.get('severity', 'medium'), 'warning'),
                "message": {
                    "text": finding.get('description', 'Security vulnerability detected')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('endpoint', finding.get('target', 'unknown'))
                            }
                        }
                    }
                ]
            })
        
        return sarif
    
    def generate_junit_xml(self, scan_results: Dict[str, Any]) -> str:
        """Generate JUnit XML format for CI/CD test reporting"""
        
        total_tests = scan_results.get('total_findings', 0)
        failures = scan_results.get('severity_counts', {}).get('critical', 0) + \
                  scan_results.get('severity_counts', {}).get('high', 0)
        
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="Scorpion Security Scan" tests="{total_tests}" failures="{failures}" time="0">
'''
        
        for finding in scan_results.get('findings', []):
            severity = finding.get('severity', 'medium')
            description = finding.get('description', 'Security issue')
            
            if severity in ['critical', 'high']:
                xml += f'''    <testcase name="{description}" classname="SecurityScan">
      <failure message="{description}">
Severity: {severity}
Evidence: {finding.get('evidence', 'N/A')}
Remediation: {finding.get('remediation', 'N/A')}
      </failure>
    </testcase>
'''
            else:
                xml += f'''    <testcase name="{description}" classname="SecurityScan" />
'''
        
        xml += '''  </testsuite>
</testsuites>'''
        
        return xml
    
    def should_fail_build(
        self, 
        scan_results: Dict[str, Any],
        fail_on_critical: bool = True,
        fail_on_high: bool = False,
        max_medium: int = 10
    ) -> tuple[bool, str]:
        """Determine if CI/CD build should fail based on findings"""
        
        severity_counts = scan_results.get('severity_counts', {})
        
        if fail_on_critical and severity_counts.get('critical', 0) > 0:
            return (True, f"Build failed: {severity_counts['critical']} critical vulnerabilities found")
        
        if fail_on_high and severity_counts.get('high', 0) > 0:
            return (True, f"Build failed: {severity_counts['high']} high severity vulnerabilities found")
        
        if severity_counts.get('medium', 0) > max_medium:
            return (True, f"Build failed: {severity_counts['medium']} medium vulnerabilities exceed threshold of {max_medium}")
        
        return (False, "Build passed security checks")
    
    def generate_github_actions_workflow(self) -> str:
        """Generate GitHub Actions workflow file"""
        
        return '''name: Scorpion Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    permissions:
      security-events: write  # For uploading SARIF results
      contents: read
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Scorpion
        run: |
          pip install -e tools/python_scorpion
      
      - name: Run API Security Scan
        run: |
          scorpion api-security \\
            --target ${{ secrets.API_URL }} \\
            --output api-security-results.json
      
      - name: Run Database Security Scan
        run: |
          scorpion db-pentest \\
            --target ${{ secrets.DB_URL }} \\
            --output db-pentest-results.json
        continue-on-error: true
      
      - name: Generate SARIF report
        run: |
          scorpion ci-scan \\
            --input api-security-results.json \\
            --sarif-output scorpion.sarif
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scorpion.sarif
      
      - name: Check security thresholds
        run: |
          scorpion ci-scan \\
            --input api-security-results.json \\
            --fail-on-critical \\
            --fail-on-high
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-scan-results
          path: |
            api-security-results.json
            db-pentest-results.json
            scorpion.sarif
'''
    
    def generate_gitlab_ci_config(self) -> str:
        """Generate GitLab CI configuration"""
        
        return '''stages:
  - security

variables:
  SCORPION_VERSION: "latest"

security_scan:
  stage: security
  image: python:3.11
  
  before_script:
    - pip install -e tools/python_scorpion
  
  script:
    - echo "Running Scorpion security scans..."
    
    # API Security Scan
    - scorpion api-security
        --target $API_URL
        --output api-security-results.json
    
    # Database Security Scan
    - scorpion db-pentest
        --target $DB_URL
        --output db-pentest-results.json
    
    # Generate SARIF for GitLab SAST
    - scorpion ci-scan
        --input api-security-results.json
        --sarif-output gl-sast-report.json
    
    # Check thresholds
    - scorpion ci-scan
        --input api-security-results.json
        --fail-on-critical
        --fail-on-high
  
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - api-security-results.json
      - db-pentest-results.json
    expire_in: 1 week
  
  allow_failure: false
  
  only:
    - main
    - merge_requests
'''
    
    def generate_jenkins_pipeline(self) -> str:
        """Generate Jenkins pipeline"""
        
        return '''pipeline {
    agent any
    
    environment {
        API_URL = credentials('api-url')
        DB_URL = credentials('db-url')
    }
    
    stages {
        stage('Setup') {
            steps {
                sh 'pip install -e tools/python_scorpion'
            }
        }
        
        stage('API Security Scan') {
            steps {
                sh """
                    scorpion api-security \\
                        --target ${API_URL} \\
                        --output api-security-results.json
                """
            }
        }
        
        stage('Database Security Scan') {
            steps {
                sh """
                    scorpion db-pentest \\
                        --target ${DB_URL} \\
                        --output db-pentest-results.json
                """
            }
        }
        
        stage('Generate Reports') {
            steps {
                sh """
                    scorpion ci-scan \\
                        --input api-security-results.json \\
                        --sarif-output scorpion.sarif \\
                        --junit-output scorpion-junit.xml
                """
            }
        }
        
        stage('Check Thresholds') {
            steps {
                sh """
                    scorpion ci-scan \\
                        --input api-security-results.json \\
                        --fail-on-critical \\
                        --fail-on-high \\
                        --max-medium 5
                """
            }
        }
    }
    
    post {
        always {
            junit 'scorpion-junit.xml'
            archiveArtifacts artifacts: '*.json,*.sarif,*.xml', fingerprint: true
        }
        failure {
            emailext (
                subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Security vulnerabilities found. Check ${env.BUILD_URL} for details.",
                to: "${env.SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
'''


async def run_ci_scan(
    input_file: str,
    fail_on_critical: bool = True,
    fail_on_high: bool = False,
    max_medium: int = 10,
    sarif_output: Optional[str] = None,
    junit_output: Optional[str] = None
) -> int:
    """Run CI/CD security scan with configurable failure thresholds"""
    
    # Load scan results
    with open(input_file, 'r') as f:
        scan_results = json.load(f)
    
    ci = CICDIntegration()
    
    # Generate SARIF if requested
    if sarif_output:
        sarif = ci.generate_sarif(scan_results)
        with open(sarif_output, 'w') as f:
            json.dump(sarif, f, indent=2)
        print(f"✅ SARIF report saved to: {sarif_output}")
    
    # Generate JUnit XML if requested
    if junit_output:
        junit_xml = ci.generate_junit_xml(scan_results)
        with open(junit_output, 'w') as f:
            f.write(junit_xml)
        print(f"✅ JUnit XML saved to: {junit_output}")
    
    # Check thresholds
    should_fail, message = ci.should_fail_build(
        scan_results,
        fail_on_critical,
        fail_on_high,
        max_medium
    )
    
    print(f"\n{'❌' if should_fail else '✅'} {message}")
    
    return 1 if should_fail else 0
