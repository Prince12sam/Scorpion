#!/usr/bin/env python3
"""
Mobile Application Security Testing Module
Android APK and iOS IPA analysis, SSL pinning bypass, dynamic analysis,
OWASP Mobile Top 10 testing, and runtime hooking with Frida.
"""

import subprocess
import zipfile
import json
import re
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import tempfile


class MobilePlatform(Enum):
    """Mobile platforms"""
    ANDROID = "Android"
    IOS = "iOS"


class MobileVulnerability(Enum):
    """OWASP Mobile Top 10 2023"""
    M1_IMPROPER_CREDENTIAL_USAGE = "M1: Improper Credential Usage"
    M2_INADEQUATE_SUPPLY_CHAIN = "M2: Inadequate Supply Chain Security"
    M3_INSECURE_AUTHENTICATION = "M3: Insecure Authentication/Authorization"
    M4_INSUFFICIENT_INPUT_VALIDATION = "M4: Insufficient Input/Output Validation"
    M5_INSECURE_COMMUNICATION = "M5: Insecure Communication"
    M6_INADEQUATE_PRIVACY_CONTROLS = "M6: Inadequate Privacy Controls"
    M7_INSUFFICIENT_BINARY_PROTECTIONS = "M7: Insufficient Binary Protections"
    M8_SECURITY_MISCONFIGURATION = "M8: Security Misconfiguration"
    M9_INSECURE_DATA_STORAGE = "M9: Insecure Data Storage"
    M10_INSUFFICIENT_CRYPTOGRAPHY = "M10: Insufficient Cryptography"


@dataclass
class MobileFinding:
    """Mobile security finding"""
    vulnerability: MobileVulnerability
    severity: str  # Critical, High, Medium, Low
    title: str
    description: str
    location: str  # File path or component
    remediation: str
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "vulnerability": self.vulnerability.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "remediation": self.remediation,
            "references": self.references
        }


@dataclass
class AppInfo:
    """Mobile application metadata"""
    package_name: str
    app_name: str
    version: str
    platform: MobilePlatform
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    exported_components: List[str] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = False
    uses_cleartext_traffic: bool = False
    certificate_info: Dict = field(default_factory=dict)


class APKAnalyzer:
    """Android APK static analysis"""
    
    def __init__(self, apk_path: Path):
        self.apk_path = apk_path
        self.temp_dir = Path(tempfile.mkdtemp())
        self.tools_available = self._check_tools()
        
    def _check_tools(self) -> Dict[str, bool]:
        """Check if analysis tools are installed"""
        tools = {
            "apktool": False,
            "jadx": False,
            "dex2jar": False,
            "jd-cli": False,
            "aapt": False
        }
        
        for tool in tools.keys():
            try:
                result = subprocess.run(
                    [tool, "--version"],
                    capture_output=True,
                    timeout=5
                )
                tools[tool] = result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                tools[tool] = False
        
        return tools
    
    def extract_apk(self) -> bool:
        """Extract APK contents"""
        print(f"📦 Extracting APK: {self.apk_path.name}")
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
            
            print(f"✅ APK extracted to: {self.temp_dir}")
            return True
        except Exception as e:
            print(f"❌ Extraction failed: {e}")
            return False
    
    def decompile_apk(self) -> Optional[Path]:
        """Decompile APK using apktool"""
        if not self.tools_available.get("apktool"):
            print("⚠️ apktool not found. Install: https://ibotpeaches.github.io/Apktool/")
            return None
        
        print(f"🔨 Decompiling APK with apktool...")
        
        output_dir = self.temp_dir / "decompiled"
        
        try:
            cmd = ["apktool", "d", str(self.apk_path), "-o", str(output_dir), "-f"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 and output_dir.exists():
                print(f"✅ Decompiled to: {output_dir}")
                return output_dir
            else:
                print(f"⚠️ Decompilation may have failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"❌ Decompilation failed: {e}")
            return None
    
    def get_app_info(self) -> Optional[AppInfo]:
        """Extract app metadata from AndroidManifest.xml"""
        manifest_path = self.temp_dir / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            self.extract_apk()
        
        if not manifest_path.exists():
            print("❌ AndroidManifest.xml not found")
            return None
        
        print(f"📋 Parsing AndroidManifest.xml...")
        
        try:
            # Use aapt to parse binary XML
            if self.tools_available.get("aapt"):
                result = subprocess.run(
                    ["aapt", "dump", "badging", str(self.apk_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    return self._parse_aapt_output(result.stdout)
            
            # Fallback: manual parsing if aapt not available
            return self._parse_manifest_fallback(manifest_path)
            
        except Exception as e:
            print(f"❌ Manifest parsing failed: {e}")
            return None
    
    def _parse_aapt_output(self, output: str) -> AppInfo:
        """Parse aapt dump output"""
        app_info = AppInfo(
            package_name="",
            app_name="",
            version="",
            platform=MobilePlatform.ANDROID
        )
        
        for line in output.split('\n'):
            # Package name
            if line.startswith("package:"):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    app_info.package_name = match.group(1)
                
                match = re.search(r"versionName='([^']+)'", line)
                if match:
                    app_info.version = match.group(1)
            
            # App name
            elif line.startswith("application-label:"):
                app_info.app_name = line.split(":", 1)[1].strip().strip("'")
            
            # SDK versions
            elif "sdkVersion:" in line:
                match = re.search(r"'(\d+)'", line)
                if match:
                    app_info.min_sdk = int(match.group(1))
            
            elif "targetSdkVersion:" in line:
                match = re.search(r"'(\d+)'", line)
                if match:
                    app_info.target_sdk = int(match.group(1))
            
            # Permissions
            elif line.startswith("uses-permission:"):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    app_info.permissions.append(match.group(1))
        
        return app_info
    
    def _parse_manifest_fallback(self, manifest_path: Path) -> AppInfo:
        """Fallback manifest parsing (simplified)"""
        # This is a simplified version - real implementation would use XML parser
        app_info = AppInfo(
            package_name="unknown",
            app_name="unknown",
            version="unknown",
            platform=MobilePlatform.ANDROID
        )
        
        return app_info
    
    def scan_security_issues(self) -> List[MobileFinding]:
        """Scan for common security issues"""
        findings = []
        
        print(f"🔍 Scanning for security issues...")
        
        # Get app info
        app_info = self.get_app_info()
        
        if app_info:
            # Check dangerous permissions
            findings.extend(self._check_dangerous_permissions(app_info))
            
            # Check debuggable flag
            if app_info.debuggable:
                findings.append(MobileFinding(
                    vulnerability=MobileVulnerability.M8_SECURITY_MISCONFIGURATION,
                    severity="High",
                    title="Application is Debuggable",
                    description="The android:debuggable flag is set to true, allowing attackers to attach debuggers and inspect runtime behavior.",
                    location="AndroidManifest.xml",
                    remediation="Set android:debuggable to false in production builds",
                    references=["https://developer.android.com/guide/topics/manifest/application-element#debug"]
                ))
            
            # Check backup flag
            if app_info.allow_backup:
                findings.append(MobileFinding(
                    vulnerability=MobileVulnerability.M9_INSECURE_DATA_STORAGE,
                    severity="Medium",
                    title="Backup Enabled",
                    description="android:allowBackup is set to true, allowing sensitive data to be backed up via adb backup.",
                    location="AndroidManifest.xml",
                    remediation="Set android:allowBackup to false or use BackupAgent with encryption",
                    references=["https://developer.android.com/guide/topics/data/backup"]
                ))
            
            # Check cleartext traffic
            if app_info.uses_cleartext_traffic:
                findings.append(MobileFinding(
                    vulnerability=MobileVulnerability.M5_INSECURE_COMMUNICATION,
                    severity="Critical",
                    title="Cleartext Traffic Allowed",
                    description="Application allows cleartext HTTP traffic, exposing data to man-in-the-middle attacks.",
                    location="AndroidManifest.xml or network_security_config.xml",
                    remediation="Set android:usesCleartextTraffic to false and enforce HTTPS",
                    references=["https://developer.android.com/training/articles/security-config"]
                ))
        
        # Scan for hardcoded secrets
        findings.extend(self._scan_hardcoded_secrets())
        
        # Scan for insecure storage
        findings.extend(self._scan_insecure_storage())
        
        print(f"✅ Found {len(findings)} security issues")
        return findings
    
    def _check_dangerous_permissions(self, app_info: AppInfo) -> List[MobileFinding]:
        """Check for dangerous permissions"""
        findings = []
        
        dangerous_perms = {
            "READ_SMS": "Can read SMS messages",
            "SEND_SMS": "Can send SMS messages",
            "READ_CONTACTS": "Can access contacts",
            "READ_CALL_LOG": "Can access call history",
            "CAMERA": "Can access camera",
            "RECORD_AUDIO": "Can record audio",
            "ACCESS_FINE_LOCATION": "Can access precise location",
            "READ_EXTERNAL_STORAGE": "Can read files",
            "WRITE_EXTERNAL_STORAGE": "Can write files"
        }
        
        for perm in app_info.permissions:
            perm_name = perm.split('.')[-1]
            if perm_name in dangerous_perms:
                findings.append(MobileFinding(
                    vulnerability=MobileVulnerability.M6_INADEQUATE_PRIVACY_CONTROLS,
                    severity="Medium",
                    title=f"Dangerous Permission: {perm_name}",
                    description=f"Application requests {perm_name} permission. {dangerous_perms[perm_name]}.",
                    location="AndroidManifest.xml",
                    remediation="Ensure permission is necessary and handle runtime permission requests properly",
                    references=["https://developer.android.com/guide/topics/permissions/overview"]
                ))
        
        return findings
    
    def _scan_hardcoded_secrets(self) -> List[MobileFinding]:
        """Scan for hardcoded API keys, passwords, etc."""
        findings = []
        
        # Patterns to search for
        patterns = {
            "API Key": r'["\']api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            "Password": r'["\']password["\']?\s*[:=]\s*["\'](.+?)["\']',
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "Private Key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'
        }
        
        # Search in decompiled code
        decompiled_dir = self.temp_dir / "decompiled"
        if decompiled_dir.exists():
            for file_path in decompiled_dir.rglob("*.smali"):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    for secret_type, pattern in patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            findings.append(MobileFinding(
                                vulnerability=MobileVulnerability.M1_IMPROPER_CREDENTIAL_USAGE,
                                severity="Critical",
                                title=f"Hardcoded {secret_type}",
                                description=f"Found hardcoded {secret_type} in source code",
                                location=str(file_path.relative_to(self.temp_dir)),
                                remediation="Move secrets to secure storage (Android Keystore) or backend",
                                references=["https://developer.android.com/training/articles/keystore"]
                            ))
                            break  # One finding per file
                except Exception:
                    pass
        
        return findings
    
    def _scan_insecure_storage(self) -> List[MobileFinding]:
        """Scan for insecure data storage"""
        findings = []
        
        # Check for SharedPreferences usage
        decompiled_dir = self.temp_dir / "decompiled"
        if decompiled_dir.exists():
            for file_path in decompiled_dir.rglob("*.smali"):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    if "getSharedPreferences" in content and "MODE_WORLD_READABLE" in content:
                        findings.append(MobileFinding(
                            vulnerability=MobileVulnerability.M9_INSECURE_DATA_STORAGE,
                            severity="High",
                            title="World-Readable SharedPreferences",
                            description="SharedPreferences with MODE_WORLD_READABLE allows other apps to access data",
                            location=str(file_path.relative_to(self.temp_dir)),
                            remediation="Use MODE_PRIVATE and consider EncryptedSharedPreferences",
                            references=["https://developer.android.com/topic/security/data"]
                        ))
                except Exception:
                    pass
        
        return findings
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)


class FridaHooker:
    """Frida dynamic instrumentation for runtime hooking"""
    
    def __init__(self, package_name: str):
        self.package_name = package_name
        self.frida_available = self._check_frida()
    
    def _check_frida(self) -> bool:
        """Check if Frida is installed"""
        try:
            import frida
            return True
        except ImportError:
            return False
    
    def bypass_ssl_pinning(self) -> bool:
        """Inject Frida script to bypass SSL pinning"""
        if not self.frida_available:
            print("❌ Frida not installed. Install: pip install frida frida-tools")
            return False
        
        print(f"🔓 Bypassing SSL pinning for {self.package_name}")
        
        # Frida script for SSL pinning bypass
        ssl_bypass_script = """
Java.perform(function() {
    console.log("[*] SSL Pinning Bypass Starting...");
    
    // Hook SSLContext
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[+] SSLContext.init() called');
        this.init(keyManager, null, secureRandom);
    };
    
    // Hook OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp CertificatePinner.check() bypassed for ' + hostname);
            return;
        };
    } catch(err) {
        console.log('[-] OkHttp not found');
    }
    
    // Hook TrustManager
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustManager = Java.registerClass({
        name: 'com.scorpion.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    console.log('[*] SSL Pinning Bypass Complete');
});
"""
        
        try:
            import frida
            
            # Attach to process
            device = frida.get_usb_device()
            pid = device.spawn([self.package_name])
            session = device.attach(pid)
            
            # Load script
            script = session.create_script(ssl_bypass_script)
            script.load()
            
            # Resume app
            device.resume(pid)
            
            print(f"✅ SSL pinning bypass loaded")
            print(f"📱 App: {self.package_name} (PID: {pid})")
            print(f"⚠️ Configure proxy to intercept traffic (e.g., Burp Suite on 127.0.0.1:8080)")
            
            return True
            
        except Exception as e:
            print(f"❌ Frida hooking failed: {e}")
            return False
    
    def hook_method(self, class_name: str, method_name: str) -> bool:
        """Hook specific method for logging or modification"""
        if not self.frida_available:
            return False
        
        hook_script = f"""
Java.perform(function() {{
    var targetClass = Java.use('{class_name}');
    targetClass.{method_name}.implementation = function() {{
        console.log('[*] {class_name}.{method_name}() called');
        console.log('    Arguments: ' + JSON.stringify(arguments));
        
        var result = this.{method_name}.apply(this, arguments);
        
        console.log('    Return value: ' + result);
        return result;
    }};
    
    console.log('[+] Hooked {class_name}.{method_name}()');
}});
"""
        
        try:
            import frida
            
            device = frida.get_usb_device()
            session = device.attach(self.package_name)
            
            script = session.create_script(hook_script)
            script.load()
            
            print(f"✅ Hooked: {class_name}.{method_name}()")
            return True
            
        except Exception as e:
            print(f"❌ Method hooking failed: {e}")
            return False


class MobileSecurityTester:
    """Main mobile security testing orchestrator"""
    
    def __init__(self):
        pass
    
    def analyze_apk(self, apk_path: Path, owasp_top10: bool = True) -> Dict:
        """
        Comprehensive APK analysis
        
        Args:
            apk_path: Path to APK file
            owasp_top10: Run OWASP Mobile Top 10 checks
        """
        print(f"="*60)
        print(f"MOBILE SECURITY ANALYSIS")
        print(f"="*60)
        print(f"APK: {apk_path.name}\n")
        
        analyzer = APKAnalyzer(apk_path)
        
        # Extract and decompile
        if not analyzer.extract_apk():
            return {"error": "Extraction failed"}
        
        decompiled_dir = analyzer.decompile_apk()
        
        # Get app info
        app_info = analyzer.get_app_info()
        
        if app_info:
            print(f"\n📱 App Information:")
            print(f"  Package: {app_info.package_name}")
            print(f"  Name: {app_info.app_name}")
            print(f"  Version: {app_info.version}")
            print(f"  Min SDK: {app_info.min_sdk}")
            print(f"  Target SDK: {app_info.target_sdk}")
            print(f"  Permissions: {len(app_info.permissions)}")
        
        # Security scan
        findings = []
        if owasp_top10:
            findings = analyzer.scan_security_issues()
        
        # Group findings by severity
        critical = [f for f in findings if f.severity == "Critical"]
        high = [f for f in findings if f.severity == "High"]
        medium = [f for f in findings if f.severity == "Medium"]
        low = [f for f in findings if f.severity == "Low"]
        
        print(f"\n🔍 Security Findings:")
        print(f"  Critical: {len(critical)}")
        print(f"  High: {len(high)}")
        print(f"  Medium: {len(medium)}")
        print(f"  Low: {len(low)}")
        
        # Show critical findings
        if critical:
            print(f"\n❌ Critical Issues:")
            for finding in critical:
                print(f"  • {finding.title}")
                print(f"    {finding.description}")
        
        # Cleanup
        analyzer.cleanup()
        
        return {
            "app_info": app_info.__dict__ if app_info else {},
            "findings": [f.to_dict() for f in findings],
            "statistics": {
                "total": len(findings),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low)
            }
        }
    
    def dynamic_analysis(self, package_name: str, bypass_ssl: bool = True) -> bool:
        """
        Dynamic analysis with Frida
        
        Args:
            package_name: Android package name (e.g., com.example.app)
            bypass_ssl: Bypass SSL pinning
        """
        print(f"🔄 Starting dynamic analysis: {package_name}")
        
        hooker = FridaHooker(package_name)
        
        if bypass_ssl:
            return hooker.bypass_ssl_pinning()
        
        return False


def main():
    """Demo mobile security testing"""
    
    print("="*60)
    print("MOBILE SECURITY TESTING DEMO")
    print("="*60)
    
    # Example APK analysis (if APK file provided)
    import sys
    
    if len(sys.argv) > 1:
        apk_path = Path(sys.argv[1])
        
        if apk_path.exists() and apk_path.suffix == '.apk':
            tester = MobileSecurityTester()
            results = tester.analyze_apk(apk_path, owasp_top10=True)
            
            # Save results
            output_file = Path("mobile_security_report.json")
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\n✅ Report saved: {output_file}")
        else:
            print(f"❌ Invalid APK file: {apk_path}")
    else:
        print("Usage: python mobile_security.py <apk_file>")
        print("\nExample:")
        print("  python mobile_security.py app.apk")


if __name__ == "__main__":
    main()
