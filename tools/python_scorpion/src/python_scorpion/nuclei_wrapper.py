"""
Production Nuclei integration for vulnerability scanning.
NO dummy data - all results from real nuclei binary execution.
Requires nuclei to be installed and available in PATH.
"""
import subprocess
import json
import os
import shutil
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class NucleiResult:
    """Nuclei scan result"""
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    extracted_results: List[str]
    type: str
    curl_command: str
    matcher_name: str
    description: str
    tags: List[str]


class NucleiScanner:
    """
    Production Nuclei wrapper for template-based vulnerability scanning.
    All functionality requires real nuclei binary - NO fallbacks.
    """
    
    def __init__(self):
        # Try multiple methods to find nuclei
        self.nuclei_path = self._find_nuclei()
        if not self.nuclei_path:
            raise FileNotFoundError(
                "Nuclei binary not found in PATH. Install from: https://github.com/projectdiscovery/nuclei\n"
                "Linux/macOS: sudo apt install nuclei OR brew install nuclei\n"
                "Windows: Download from https://github.com/projectdiscovery/nuclei/releases"
            )
    
    def _find_nuclei(self) -> Optional[str]:
        """Find nuclei binary using multiple methods"""
        return _find_nuclei_binary()
    
    def check_updates(self) -> bool:
        """Check for nuclei template updates"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def list_templates(self, tags: Optional[List[str]] = None) -> List[str]:
        """
        List available nuclei templates.
        Returns template IDs based on tags filter.
        """
        cmd = [self.nuclei_path, "-tl"]
        
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                # Parse template list from output
                templates = []
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("[") and not line.startswith("Total"):
                        templates.append(line)
                return templates
            else:
                return []
        except Exception:
            return []
    
    def scan(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        rate_limit: int = 150,
        concurrency: int = 25,
        timeout: int = 10,
        retries: int = 1,
        output_file: Optional[str] = None,
        include_tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        exclude_severity: Optional[List[str]] = None,
        silent: bool = False,
    ) -> List[Dict]:
        """
        Execute nuclei scan with production configuration.
        NO dummy data - all results from real nuclei execution.
        
        Args:
            target: Target URL or file with URLs
            templates: Specific template paths/IDs to use
            tags: Template tags to include (cve, xss, sqli, etc.)
            severity: Filter by severity (critical, high, medium, low, info)
            rate_limit: Requests per second
            concurrency: Template concurrency
            timeout: Request timeout in seconds
            retries: Number of retries on failure
            output_file: JSON output file path
            include_tags: Additional tags to include
            exclude_tags: Tags to exclude
            exclude_severity: Severity levels to exclude
            silent: Suppress progress output
        
        Returns:
            List of vulnerability findings as dictionaries
        """
        cmd = [self.nuclei_path, "-u", target, "-json"]
        
        # Templates
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        
        # Tags
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        if include_tags:
            cmd.extend(["-itags", ",".join(include_tags)])
        
        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])
        
        # Severity
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        if exclude_severity:
            cmd.extend(["-exclude-severity", ",".join(exclude_severity)])
        
        # Performance
        cmd.extend(["-rate-limit", str(rate_limit)])
        cmd.extend(["-concurrency", str(concurrency)])
        cmd.extend(["-timeout", str(timeout)])
        cmd.extend(["-retries", str(retries)])
        
        # Output
        if silent:
            cmd.append("-silent")
        
        # Capture output
        output_lines = []
        
        try:
            # Run nuclei and capture JSONL output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            # Read output line by line
            for line in process.stdout:
                line = line.strip()
                if line and line.startswith("{"):
                    output_lines.append(line)
                    
                    # Write to file if specified
                    if output_file:
                        with open(output_file, 'a', encoding='utf-8') as f:
                            f.write(line + "\n")
            
            process.wait(timeout=3600)  # 1 hour max
            
        except subprocess.TimeoutExpired:
            process.kill()
            raise TimeoutError("Nuclei scan exceeded timeout")
        except Exception as e:
            raise RuntimeError(f"Nuclei scan failed: {str(e)}")
        
        # Parse JSON results
        results = []
        for line in output_lines:
            try:
                data = json.loads(line)
                results.append(data)
            except json.JSONDecodeError:
                continue
        
        return results
    
    def scan_multiple_targets(
        self,
        targets_file: str,
        **kwargs
    ) -> List[Dict]:
        """
        Scan multiple targets from a file.
        NO dummy data - real nuclei execution only.
        
        Args:
            targets_file: Path to file containing target URLs (one per line)
            **kwargs: Same arguments as scan() method
        
        Returns:
            List of vulnerability findings
        """
        if not os.path.exists(targets_file):
            raise FileNotFoundError(f"Targets file not found: {targets_file}")
        
        cmd = [self.nuclei_path, "-l", targets_file, "-json"]
        
        # Apply same options as single-target scan
        templates = kwargs.get("templates")
        tags = kwargs.get("tags")
        severity = kwargs.get("severity")
        rate_limit = kwargs.get("rate_limit", 150)
        concurrency = kwargs.get("concurrency", 25)
        timeout = kwargs.get("timeout", 10)
        retries = kwargs.get("retries", 1)
        output_file = kwargs.get("output_file")
        include_tags = kwargs.get("include_tags")
        exclude_tags = kwargs.get("exclude_tags")
        exclude_severity = kwargs.get("exclude_severity")
        silent = kwargs.get("silent", False)
        
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        if include_tags:
            cmd.extend(["-itags", ",".join(include_tags)])
        
        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])
        
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        if exclude_severity:
            cmd.extend(["-exclude-severity", ",".join(exclude_severity)])
        
        cmd.extend(["-rate-limit", str(rate_limit)])
        cmd.extend(["-concurrency", str(concurrency)])
        cmd.extend(["-timeout", str(timeout)])
        cmd.extend(["-retries", str(retries)])
        
        if silent:
            cmd.append("-silent")
        
        output_lines = []
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            for line in process.stdout:
                line = line.strip()
                if line and line.startswith("{"):
                    output_lines.append(line)
                    
                    if output_file:
                        with open(output_file, 'a', encoding='utf-8') as f:
                            f.write(line + "\n")
            
            process.wait(timeout=7200)  # 2 hours for multiple targets
            
        except subprocess.TimeoutExpired:
            process.kill()
            raise TimeoutError("Nuclei multi-target scan exceeded timeout")
        except Exception as e:
            raise RuntimeError(f"Nuclei scan failed: {str(e)}")
        
        results = []
        for line in output_lines:
            try:
                data = json.loads(line)
                results.append(data)
            except json.JSONDecodeError:
                continue
        
        return results


def _find_nuclei_binary() -> Optional[str]:
    """Find nuclei binary using multiple methods (standalone function)"""
    # Method 1: Standard PATH search
    nuclei_path = shutil.which("nuclei")
    if nuclei_path:
        return nuclei_path
    
    # Method 2: Common installation locations
    common_paths = [
        "/usr/bin/nuclei",              # Debian/Ubuntu apt
        "/usr/local/bin/nuclei",        # Manual install
        "/opt/nuclei/nuclei",           # Alternative install
        os.path.expanduser("~/go/bin/nuclei"),  # Go install
        os.path.expanduser("~/.local/bin/nuclei"),  # User install
        "/snap/bin/nuclei",             # Snap install
    ]
    
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    
    # Method 3: Try to find in full system PATH (bypass venv)
    try:
        result = subprocess.run(
            ["which", "nuclei"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            found_path = result.stdout.strip()
            if found_path and os.path.isfile(found_path):
                return found_path
    except Exception:
        pass
    
    return None

def get_nuclei_version() -> Optional[str]:
    """Get installed nuclei version. Returns None if not installed."""
    # Use the same enhanced detection as NucleiScanner
    nuclei_path = _find_nuclei_binary()
    if not nuclei_path:
        return None
    
    try:
        result = subprocess.run(
            [nuclei_path, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        if result.returncode == 0:
            # Parse version from output (nuclei writes to stderr)
            output = result.stderr + result.stdout
            for line in output.splitlines():
                if "nuclei" in line.lower():
                    return line.strip()
        
        return None
    except Exception:
        return None