"""
API Security Testing Module
Comprehensive REST/GraphQL/gRPC API penetration testing
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import aiohttp
import jwt
from urllib.parse import urlparse, urljoin


@dataclass
class APIEndpoint:
    """Represents an API endpoint"""
    method: str
    path: str
    params: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    rate_limited: bool = False


@dataclass
class APISecurityFinding:
    """Security finding for API testing"""
    severity: str  # critical, high, medium, low, info
    category: str
    endpoint: str
    description: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


class APISecurityTester:
    """Comprehensive API Security Testing"""
    
    def __init__(self, base_url: str, timeout: int = 10, max_connections: int = 100):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_connections = max_connections
        self.endpoints: List[APIEndpoint] = []
        self.findings: List[APISecurityFinding] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
    async def __aenter__(self):
        # Configure connection pool with limits for better resource management
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=30,
            ttl_dns_cache=300,
            enable_cleanup_closed=True
        )
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=connector
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def discover_endpoints(self, openapi_spec_url: Optional[str] = None) -> List[APIEndpoint]:
        """Discover API endpoints from OpenAPI/Swagger spec or crawling"""
        endpoints = []
        
        if not self.session:
            return endpoints
        
        # Try OpenAPI/Swagger spec
        if openapi_spec_url:
            spec_endpoints = await self._parse_openapi_spec(openapi_spec_url)
            endpoints.extend(spec_endpoints)
        
        # Common API paths to try
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/graphql', '/swagger', '/docs',
            '/api-docs', '/openapi.json', '/swagger.json', '/swagger.yaml',
            '/api/users', '/api/admin', '/api/auth', '/api/login'
        ]
        
        for path in common_paths:
            url = urljoin(self.base_url, path)
            try:
                async with self.session.get(url, allow_redirects=False) as resp:
                    if resp.status < 400:
                        endpoints.append(APIEndpoint(method='GET', path=path))
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        
        self.endpoints = endpoints
        return endpoints
    
    async def _parse_openapi_spec(self, spec_url: str) -> List[APIEndpoint]:
        """Parse OpenAPI/Swagger specification"""
        endpoints = []
        if not self.session:
            return endpoints
        try:
            async with self.session.get(spec_url) as resp:
                if resp.status == 200:
                    spec = await resp.json()
                    paths = spec.get('paths', {})
                    for path, methods in paths.items():
                        for method in methods.keys():
                            if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                                params = []
                                method_spec = methods[method]
                                if 'parameters' in method_spec:
                                    params = [p['name'] for p in method_spec['parameters']]
                                
                                endpoints.append(APIEndpoint(
                                    method=method.upper(),
                                    path=path,
                                    params=params,
                                    auth_required='security' in method_spec
                                ))
        except (aiohttp.ClientError, json.JSONDecodeError, KeyError):
            pass
        return endpoints
    
    async def test_authentication(self) -> List[APISecurityFinding]:
        """Test authentication mechanisms"""
        findings = []
        
        if not self.session:
            return findings
        
        # Test for broken authentication
        test_endpoints = ['/api/login', '/api/auth', '/api/token']
        
        for path in test_endpoints:
            url = urljoin(self.base_url, path)
            
            # Test SQL injection in auth
            sqli_payloads = ["' OR '1'='1", "admin' --", "' OR 1=1--"]
            for payload in sqli_payloads:
                try:
                    data = {'username': payload, 'password': payload}
                    async with self.session.post(url, json=data) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if 'token' in body.lower() or 'success' in body.lower():
                                findings.append(APISecurityFinding(
                                    severity='critical',
                                    category='authentication',
                                    endpoint=path,
                                    description='SQL Injection in authentication endpoint',
                                    evidence=f'Payload: {payload}, Status: {resp.status}',
                                    remediation='Use parameterized queries, input validation',
                                    cwe_id='CWE-89'
                                ))
                except:
                    pass
        
        # Test default credentials
        default_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
            ('test', 'test'), ('admin', '12345'), ('user', 'user')
        ]
        
        for username, password in default_creds:
            for path in test_endpoints:
                url = urljoin(self.base_url, path)
                try:
                    data = {'username': username, 'password': password}
                    async with self.session.post(url, json=data) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if 'token' in body.lower():
                                findings.append(APISecurityFinding(
                                    severity='critical',
                                    category='authentication',
                                    endpoint=path,
                                    description=f'Default credentials accepted: {username}:{password}',
                                    evidence=f'Login successful with default credentials',
                                    remediation='Enforce strong password policy, remove default accounts',
                                    cwe_id='CWE-798'
                                ))
                except:
                    pass
        
        return findings
    
    async def test_jwt_security(self, token: Optional[str] = None) -> List[APISecurityFinding]:
        """Test JWT token security"""
        findings = []
        
        if not token:
            return findings
        
        try:
            # Decode JWT without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # Check for sensitive data in JWT
            sensitive_keys = ['password', 'secret', 'key', 'api_key', 'ssn', 'credit_card']
            for key in decoded.keys():
                if any(s in key.lower() for s in sensitive_keys):
                    findings.append(APISecurityFinding(
                        severity='high',
                        category='jwt_security',
                        endpoint='/api/token',
                        description=f'Sensitive data in JWT: {key}',
                        evidence=f'JWT contains sensitive field: {key}',
                        remediation='Remove sensitive data from JWT payload',
                        cwe_id='CWE-359'
                    ))
            
            # Test alg:none vulnerability
            if self.session:
                try:
                    none_token = jwt.encode(decoded, key='', algorithm='none')
                    # Try using the none token
                    async with self.session.get(
                        urljoin(self.base_url, '/api/user'),
                        headers={'Authorization': f'Bearer {none_token}'}
                    ) as resp:
                        if resp.status == 200:
                            findings.append(APISecurityFinding(
                                severity='critical',
                                category='jwt_security',
                                endpoint='/api/*',
                                description='JWT accepts alg:none (algorithm confusion)',
                                evidence='Server accepted unsigned JWT token',
                                remediation='Reject tokens with alg:none, validate algorithm',
                                cwe_id='CWE-347',
                                cvss_score=9.1
                            ))
                except:
                    pass
            
            # Test weak signing key
            weak_keys = ['secret', 'key', 'password', '12345', 'admin', 'test']
            for weak_key in weak_keys:
                try:
                    jwt.decode(token, weak_key, algorithms=['HS256'])
                    findings.append(APISecurityFinding(
                        severity='critical',
                        category='jwt_security',
                        endpoint='/api/token',
                        description=f'JWT signed with weak key: {weak_key}',
                        evidence=f'JWT signature verified with weak key',
                        remediation='Use cryptographically strong signing keys (>256 bits)',
                        cwe_id='CWE-326',
                        cvss_score=8.7
                    ))
                    break
                except:
                    pass
        
        except Exception as e:
            pass
        
        return findings
    
    async def test_idor(self) -> List[APISecurityFinding]:
        """Test for Insecure Direct Object Reference (IDOR)"""
        findings = []
        
        if not self.session:
            return findings
        
        # Common IDOR patterns
        idor_endpoints = [
            '/api/user/{id}', '/api/users/{id}', '/api/profile/{id}',
            '/api/account/{id}', '/api/order/{id}', '/api/invoice/{id}'
        ]
        
        for endpoint_pattern in idor_endpoints:
            # Try sequential IDs
            for user_id in [1, 2, 3, 100, 1000]:
                endpoint = endpoint_pattern.replace('{id}', str(user_id))
                url = urljoin(self.base_url, endpoint)
                
                try:
                    async with self.session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data:
                                findings.append(APISecurityFinding(
                                    severity='high',
                                    category='authorization',
                                    endpoint=endpoint,
                                    description=f'IDOR vulnerability - Access to user {user_id} data',
                                    evidence=f'Accessed user data without authorization: {json.dumps(data)[:200]}',
                                    remediation='Implement proper authorization checks, use UUIDs instead of sequential IDs',
                                    cwe_id='CWE-639',
                                    cvss_score=7.5
                                ))
                                break  # Found IDOR, no need to test more IDs
                except:
                    pass
        
        return findings
    
    async def test_graphql(self, graphql_endpoint: str = '/graphql') -> List[APISecurityFinding]:
        """Test GraphQL-specific vulnerabilities"""
        findings = []
        
        if not self.session:
            return findings
        
        url = urljoin(self.base_url, graphql_endpoint)
        
        # Test introspection
        introspection_query = {
            'query': '''
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                        }
                    }
                }
            }
            '''
        }
        
        try:
            async with self.session.post(url, json=introspection_query) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if '__schema' in str(data):
                        findings.append(APISecurityFinding(
                            severity='medium',
                            category='graphql',
                            endpoint=graphql_endpoint,
                            description='GraphQL introspection enabled in production',
                            evidence='Full schema exposed via introspection',
                            remediation='Disable introspection in production environments',
                            cwe_id='CWE-200'
                        ))
        except:
            pass
        
        # Test for DoS via deeply nested queries
        nested_query = {
            'query': '''
            {
                user {
                    posts {
                        comments {
                            author {
                                posts {
                                    comments {
                                        author {
                                            posts {
                                                comments {
                                                    text
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            '''
        }
        
        try:
            start = datetime.now()
            async with self.session.post(url, json=nested_query) as resp:
                duration = (datetime.now() - start).total_seconds()
                if duration > 5:
                    findings.append(APISecurityFinding(
                        severity='high',
                        category='graphql',
                        endpoint=graphql_endpoint,
                        description='GraphQL vulnerable to DoS via deeply nested queries',
                        evidence=f'Query took {duration}s to execute',
                        remediation='Implement query depth limiting and complexity analysis',
                        cwe_id='CWE-400'
                    ))
        except:
            pass
        
        return findings
    
    async def test_rate_limiting(self) -> List[APISecurityFinding]:
        """Test for missing or weak rate limiting"""
        findings = []
        
        if not self.session:
            return findings
        
        test_endpoints = ['/api/login', '/api/register', '/api/search']
        
        for path in test_endpoints:
            url = urljoin(self.base_url, path)
            
            # Send rapid requests
            requests_allowed = 0
            for i in range(100):
                try:
                    async with self.session.get(url) as resp:
                        if resp.status != 429:  # Not rate limited
                            requests_allowed += 1
                        else:
                            break
                except:
                    break
            
            if requests_allowed >= 50:
                findings.append(APISecurityFinding(
                    severity='medium',
                    category='rate_limiting',
                    endpoint=path,
                    description='Missing or insufficient rate limiting',
                    evidence=f'Allowed {requests_allowed} requests without rate limiting',
                    remediation='Implement rate limiting (e.g., 10 req/min per IP)',
                    cwe_id='CWE-770'
                ))
        
        return findings
    
    async def test_mass_assignment(self) -> List[APISecurityFinding]:
        """Test for mass assignment vulnerabilities"""
        findings = []
        
        if not self.session:
            return findings
        
        # Common endpoints that might have mass assignment
        test_endpoints = ['/api/user', '/api/profile', '/api/account']
        
        # Try to inject admin/privileged fields
        malicious_fields = {
            'is_admin': True,
            'role': 'admin',
            'admin': True,
            'permissions': 'all',
            'isAdmin': True,
            'user_type': 'admin'
        }
        
        for path in test_endpoints:
            url = urljoin(self.base_url, path)
            
            try:
                # Try POST
                async with self.session.post(url, json=malicious_fields) as resp:
                    if resp.status in [200, 201]:
                        body = await resp.text()
                        if any(field in body for field in malicious_fields.keys()):
                            findings.append(APISecurityFinding(
                                severity='critical',
                                category='mass_assignment',
                                endpoint=path,
                                description='Mass assignment vulnerability allows privilege escalation',
                                evidence=f'Injected privileged fields accepted: {list(malicious_fields.keys())}',
                                remediation='Use allowlists for allowed fields, avoid direct object binding',
                                cwe_id='CWE-915',
                                cvss_score=8.8
                            ))
                            break
            except:
                pass
        
        return findings
    
    async def run_full_assessment(self, openapi_spec: Optional[str] = None, jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Run comprehensive API security assessment"""
        
        print(f"🔍 Discovering API endpoints...")
        await self.discover_endpoints(openapi_spec)
        print(f"✅ Found {len(self.endpoints)} endpoints")
        
        print(f"\n🔐 Testing authentication...")
        auth_findings = await self.test_authentication()
        self.findings.extend(auth_findings)
        print(f"✅ Found {len(auth_findings)} authentication issues")
        
        if jwt_token:
            print(f"\n🎫 Testing JWT security...")
            jwt_findings = await self.test_jwt_security(jwt_token)
            self.findings.extend(jwt_findings)
            print(f"✅ Found {len(jwt_findings)} JWT issues")
        
        print(f"\n🔓 Testing for IDOR vulnerabilities...")
        idor_findings = await self.test_idor()
        self.findings.extend(idor_findings)
        print(f"✅ Found {len(idor_findings)} IDOR issues")
        
        print(f"\n⚡ Testing GraphQL security...")
        graphql_findings = await self.test_graphql()
        self.findings.extend(graphql_findings)
        print(f"✅ Found {len(graphql_findings)} GraphQL issues")
        
        print(f"\n⏱️  Testing rate limiting...")
        rate_findings = await self.test_rate_limiting()
        self.findings.extend(rate_findings)
        print(f"✅ Found {len(rate_findings)} rate limiting issues")
        
        print(f"\n💉 Testing mass assignment...")
        mass_findings = await self.test_mass_assignment()
        self.findings.extend(mass_findings)
        print(f"✅ Found {len(mass_findings)} mass assignment issues")
        
        # Generate summary
        severity_counts = {
            'critical': len([f for f in self.findings if f.severity == 'critical']),
            'high': len([f for f in self.findings if f.severity == 'high']),
            'medium': len([f for f in self.findings if f.severity == 'medium']),
            'low': len([f for f in self.findings if f.severity == 'low']),
            'info': len([f for f in self.findings if f.severity == 'info'])
        }
        
        return {
            'target': self.base_url,
            'timestamp': datetime.now().isoformat(),
            'endpoints_discovered': len(self.endpoints),
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'findings': [
                {
                    'severity': f.severity,
                    'category': f.category,
                    'endpoint': f.endpoint,
                    'description': f.description,
                    'evidence': f.evidence,
                    'remediation': f.remediation,
                    'cwe_id': f.cwe_id,
                    'cvss_score': f.cvss_score
                }
                for f in self.findings
            ]
        }
