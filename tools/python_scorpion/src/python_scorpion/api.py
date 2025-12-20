import asyncio
from typing import Dict, Optional, List, Any
import httpx
import json
import base64
import hashlib
from urllib.parse import urljoin, urlparse

async def fetch_swagger(host: str, protocol: str = "https") -> Optional[Dict]:
    """Discover and parse API documentation (Swagger/OpenAPI)"""
    paths = [
        "/swagger.json", "/swagger.yaml",
        "/v2/api-docs", "/v3/api-docs",
        "/openapi.json", "/openapi.yaml",
        "/api/swagger.json", "/api/openapi.json",
        "/api-docs", "/api/docs",
        "/swagger/v1/swagger.json",
        "/api/swagger/index.html",
        "/__swagger__/", "/redoc",
        "/api.json", "/api.yaml"
    ]
    base = f"{protocol}://{host}"
    findings = []
    
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
        for p in paths:
            try:
                url = base + p
                r = await client.get(url)
                if r.status_code == 200:
                    content_type = r.headers.get("content-type", "")
                    # Check if it's JSON or YAML API docs
                    if any(ct in content_type for ct in ["json", "yaml", "text/plain"]):
                        findings.append({
                            "url": url,
                            "status": r.status_code,
                            "type": "swagger" if "swagger" in p else "openapi",
                            "content_length": len(r.content),
                            "exposed": True
                        })
                        # Try to parse endpoints
                        if "json" in content_type:
                            try:
                                spec = r.json()
                                endpoints = _extract_endpoints_from_spec(spec)
                                return {
                                    "url": url,
                                    "spec": spec,
                                    "endpoints": endpoints,
                                    "exposed": True
                                }
                            except:
                                pass
            except Exception:
                continue
    
    return {"exposed": False, "endpoints": []} if not findings else findings[0]

def _extract_endpoints_from_spec(spec: Dict) -> List[Dict]:
    """Extract API endpoints from OpenAPI/Swagger spec"""
    endpoints = []
    paths = spec.get("paths", {})
    
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "parameters": details.get("parameters", []),
                    "requires_auth": any("security" in k for k in details.keys())
                })
    
    return endpoints

async def check_graphql(host: str, protocol: str = "https") -> Dict:
    """Test GraphQL endpoints for introspection and vulnerabilities"""
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/api/query"]
    base = f"{protocol}://{host}"
    results = []
    
    for endpoint in endpoints:
        url = base + endpoint
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Test 1: Introspection query
                introspection_query = {
                    "query": "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"
                }
                r = await client.post(url, json=introspection_query)
                
                if r.status_code == 200:
                    try:
                        data = r.json()
                        has_schema = "__schema" in str(data)
                        has_types = "types" in str(data)
                        
                        # Test 2: Check for common GraphQL vulnerabilities
                        # Batch query attack
                        batch_query = {"query": "{ __typename }" * 100}
                        r_batch = await client.post(url, json=batch_query)
                        
                        # Depth attack
                        deep_query = {"query": "{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } } }"}
                        r_depth = await client.post(url, json=deep_query)
                        
                        results.append({
                            "endpoint": url,
                            "status_code": r.status_code,
                            "introspection_enabled": has_schema,
                            "schema_accessible": has_types,
                            "batch_query_allowed": r_batch.status_code == 200,
                            "deep_nesting_allowed": r_depth.status_code == 200,
                            "vulnerable": has_schema or r_batch.status_code == 200 or r_depth.status_code == 200
                        })
                    except:
                        pass
        except Exception:
            continue
    
    return {"tests": results, "vulnerable": any(r.get("vulnerable") for r in results)}

async def jwt_comprehensive_test(host: str, protocol: str = "https") -> Dict:
    """Comprehensive JWT security testing"""
    url = f"{protocol}://{host}/"
    findings = []
    
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            # Test 1: Check for JWT in headers/cookies
            r = await client.get(url)
            
            # Header leaks
            jwt_headers = ["x-jwt-token", "x-access-token", "authorization", "x-auth-token"]
            for header in jwt_headers:
                if r.headers.get(header):
                    token = r.headers.get(header)
                    findings.append({
                        "type": "jwt_header_exposure",
                        "location": header,
                        "token_preview": token[:20] + "..." if len(token) > 20 else token,
                        "severity": "high"
                    })
                    
                    # Analyze JWT if it looks like one
                    if "." in token and token.count(".") >= 2:
                        jwt_analysis = _analyze_jwt(token.replace("Bearer ", ""))
                        findings.extend(jwt_analysis)
            
            # Cookie leaks
            for cookie in r.cookies:
                if any(keyword in cookie.lower() for keyword in ["jwt", "token", "auth", "session"]):
                    findings.append({
                        "type": "jwt_cookie_exposure",
                        "location": f"cookie:{cookie}",
                        "value_preview": str(r.cookies[cookie])[:20] + "...",
                        "severity": "medium"
                    })
            
            # Test 2: Check for JWT in response body
            if "eyJ" in r.text:  # JWT typically starts with eyJ (base64 of {"alg")
                findings.append({
                    "type": "jwt_in_response_body",
                    "severity": "high",
                    "description": "JWT token found in response body"
                })
            
            # Test 3: Test common JWT vulnerabilities
            # Try "none" algorithm attack
            test_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            r_none = await client.get(url, headers={"Authorization": f"Bearer {test_jwt}"})
            if r_none.status_code in [200, 301, 302]:
                findings.append({
                    "type": "jwt_none_algorithm_accepted",
                    "severity": "critical",
                    "description": "Server accepts JWT with 'none' algorithm - CRITICAL VULNERABILITY"
                })
    
    except Exception as e:
        pass
    
    return {"findings": findings, "vulnerable": len(findings) > 0}

def _analyze_jwt(token: str) -> List[Dict]:
    """Analyze JWT token for vulnerabilities"""
    findings = []
    
    try:
        # Split JWT
        parts = token.split(".")
        if len(parts) != 3:
            return findings
        
        # Decode header
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        
        # Check for weak algorithms
        alg = header.get("alg", "").lower()
        if alg in ["none", "hs256"]:
            findings.append({
                "type": "jwt_weak_algorithm",
                "algorithm": alg,
                "severity": "high" if alg == "none" else "medium",
                "description": f"JWT uses weak algorithm: {alg}"
            })
        
        # Check for sensitive data in payload
        sensitive_keys = ["password", "secret", "api_key", "private_key", "ssn", "credit_card"]
        for key in payload.keys():
            if any(s in key.lower() for s in sensitive_keys):
                findings.append({
                    "type": "jwt_sensitive_data",
                    "key": key,
                    "severity": "high",
                    "description": f"Sensitive data '{key}' in JWT payload"
                })
        
        # Check expiration
        if "exp" not in payload:
            findings.append({
                "type": "jwt_no_expiration",
                "severity": "medium",
                "description": "JWT has no expiration time"
            })
    
    except Exception:
        pass
    
    return findings

async def idor_comprehensive_test(host: str, protocol: str = "https") -> Dict:
    """Comprehensive IDOR (Insecure Direct Object Reference) testing"""
    base = f"{protocol}://{host}"
    
    # Test multiple common API patterns
    patterns = [
        # User endpoints
        ("/api/users/{id}", [1, 2, 100, 999]),
        ("/api/user/{id}", [1, 2, 100, 999]),
        ("/api/v1/users/{id}", [1, 2, 100, 999]),
        ("/users/{id}", [1, 2, 100, 999]),
        ("/user/{id}/profile", [1, 2, 100, 999]),
        
        # Order/transaction endpoints
        ("/api/orders/{id}", [1, 2, 100, 999]),
        ("/api/order/{id}", [1, 2, 100, 999]),
        ("/api/transactions/{id}", [1, 2, 100, 999]),
        
        # Document endpoints
        ("/api/documents/{id}", [1, 2, 100, 999]),
        ("/api/files/{id}", [1, 2, 100, 999]),
        
        # Common items
        ("/api/items/{id}", [1, 2, 100, 999]),
        ("/api/products/{id}", [1, 2, 100, 999]),
        
        # Admin endpoints (high value)
        ("/api/admin/users/{id}", [1, 2]),
        ("/admin/api/users/{id}", [1, 2]),
    ]
    
    results = []
    vulnerabilities_found = []
    
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
        for pattern, test_ids in patterns:
            responses = []
            
            for test_id in test_ids:
                endpoint = pattern.replace("{id}", str(test_id))
                url = base + endpoint
                
                try:
                    # Test GET requests
                    r = await client.get(url)
                    responses.append({
                        "id": test_id,
                        "status": r.status_code,
                        "content_length": len(r.content),
                        "content_hash": hashlib.md5(r.content).hexdigest()
                    })
                    
                    # Also test with common headers
                    if r.status_code == 401 or r.status_code == 403:
                        # Try with fake auth
                        r_auth = await client.get(url, headers={"Authorization": "Bearer fake_token"})
                        if r_auth.status_code == 200:
                            responses[-1]["bypassed_auth"] = True
                
                except Exception:
                    continue
            
            # Analyze responses for IDOR indicators
            if len(responses) >= 2:
                # Check if different IDs return different data
                successful_responses = [r for r in responses if r["status"] == 200]
                
                if len(successful_responses) >= 2:
                    # Different content for different IDs = likely IDOR
                    unique_hashes = set(r["content_hash"] for r in successful_responses)
                    if len(unique_hashes) > 1:
                        vulnerabilities_found.append({
                            "endpoint_pattern": pattern,
                            "severity": "critical" if "/admin/" in pattern else "high",
                            "type": "idor_confirmed",
                            "description": f"IDOR vulnerability: Different IDs return different data without authentication",
                            "tested_ids": test_ids[:3],
                            "responses": successful_responses[:3]
                        })
                
                # Check for auth bypass
                if any(r.get("bypassed_auth") for r in responses):
                    vulnerabilities_found.append({
                        "endpoint_pattern": pattern,
                        "severity": "critical",
                        "type": "auth_bypass",
                        "description": "Authentication bypass with fake token"
                    })
            
            results.append({
                "pattern": pattern,
                "responses": responses
            })
    
    return {
        "tests": results,
        "vulnerabilities": vulnerabilities_found,
        "vulnerable": len(vulnerabilities_found) > 0
    }

async def test_mass_assignment(host: str, protocol: str = "https") -> Dict:
    """Test for mass assignment vulnerabilities"""
    base = f"{protocol}://{host}"
    endpoints = [
        "/api/users", "/api/user",
        "/api/register", "/api/signup",
        "/api/profile", "/api/account"
    ]
    
    vulnerabilities = []
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        for endpoint in endpoints:
            url = base + endpoint
            
            # Test with admin/role injection
            payloads = [
                {"email": "test@test.com", "password": "test123", "role": "admin", "isAdmin": True},
                {"email": "test@test.com", "password": "test123", "is_admin": 1, "admin": True},
                {"email": "test@test.com", "password": "test123", "privileges": ["admin", "superuser"]},
            ]
            
            for payload in payloads:
                try:
                    r = await client.post(url, json=payload)
                    if r.status_code in [200, 201]:
                        # Check if server accepted the extra fields
                        response_lower = r.text.lower()
                        if any(keyword in response_lower for keyword in ["admin", "role", "privilege"]):
                            vulnerabilities.append({
                                "endpoint": url,
                                "severity": "critical",
                                "type": "mass_assignment",
                                "payload": payload,
                                "description": "Server may accept unauthorized role/privilege fields"
                            })
                            break
                except Exception:
                    continue
    
    return {"vulnerabilities": vulnerabilities, "vulnerable": len(vulnerabilities) > 0}

async def test_api_injection(host: str, protocol: str = "https") -> Dict:
    """Test for SQL injection and NoSQL injection in APIs"""
    base = f"{protocol}://{host}"
    endpoints = [
        "/api/users?id={payload}",
        "/api/search?q={payload}",
        "/api/items?filter={payload}",
        "/api/products?id={payload}",
    ]
    
    # SQL Injection payloads
    sqli_payloads = [
        "1' OR '1'='1",
        "1' OR 1=1--",
        "' OR 1=1--",
        "admin'--",
        "1' UNION SELECT NULL--",
    ]
    
    # NoSQL injection payloads
    nosql_payloads = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
    ]
    
    vulnerabilities = []
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        for endpoint in endpoints:
            # Test SQL injection
            for payload in sqli_payloads:
                url = base + endpoint.replace("{payload}", payload)
                try:
                    r = await client.get(url)
                    # Look for SQL error signatures
                    if r.status_code == 200 or r.status_code == 500:
                        error_signatures = [
                            "sql", "mysql", "sqlite", "postgresql", "oracle",
                            "syntax error", "unexpected", "warning",
                            "database", "query failed"
                        ]
                        if any(sig in r.text.lower() for sig in error_signatures):
                            vulnerabilities.append({
                                "endpoint": endpoint,
                                "type": "sql_injection",
                                "severity": "critical",
                                "payload": payload,
                                "response_code": r.status_code,
                                "description": "Possible SQL injection vulnerability detected"
                            })
                            break
                except Exception:
                    continue
            
            # Test NoSQL injection (for JSON endpoints)
            for payload in nosql_payloads:
                url = base + endpoint.split("?")[0]  # Remove query string
                try:
                    r = await client.post(url, json={"filter": payload})
                    if r.status_code == 200:
                        # Large response might indicate data dump
                        if len(r.content) > 5000:
                            vulnerabilities.append({
                                "endpoint": url,
                                "type": "nosql_injection",
                                "severity": "critical",
                                "payload": payload,
                                "description": "Possible NoSQL injection - large data dump received"
                            })
                except Exception:
                    continue
    
    return {"vulnerabilities": vulnerabilities, "vulnerable": len(vulnerabilities) > 0}

async def improved_rate_limit(host: str, bursts: int = 50, protocol: str = "https") -> Dict:
    """Enhanced rate limiting detection with multiple endpoints"""
    endpoints = [
        "/", "/api", "/api/users", "/login", "/api/search"
    ]
    base = f"{protocol}://{host}"
    results = []
    
    for endpoint in endpoints:
        url = base + endpoint
        status_codes = []
        response_times = []
        
        async with httpx.AsyncClient(timeout=3.0) as client:
            import time
            for _ in range(bursts):
                try:
                    start = time.time()
                    r = await client.get(url)
                    elapsed = time.time() - start
                    
                    status_codes.append(r.status_code)
                    response_times.append(elapsed)
                except Exception:
                    status_codes.append(0)
                    response_times.append(0)
        
        # Analyze results
        rate_limited = 429 in status_codes
        blocked = 403 in status_codes or 503 in status_codes
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        results.append({
            "endpoint": url,
            "rate_limited": rate_limited,
            "blocked": blocked,
            "status_codes_summary": {
                "429_count": status_codes.count(429),
                "403_count": status_codes.count(403),
                "200_count": status_codes.count(200)
            },
            "avg_response_time": round(avg_response_time, 3),
            "vulnerable": not rate_limited and not blocked  # No rate limiting = vulnerable
        })
    
    return {
        "tests": results,
        "rate_limit_detected": any(r["rate_limited"] for r in results),
        "vulnerable": all(r["vulnerable"] for r in results)
    }

async def api_probe(host: str, protocol: str = "https", aggressive: bool = True) -> Dict:
    """Comprehensive API security testing
    
    Args:
        host: Target hostname
        protocol: http or https
        aggressive: Enable aggressive testing (IDOR, injection, mass assignment)
    """
    print("[API-TEST] Starting comprehensive API security assessment...")
    
    # Run all tests in parallel for speed
    tasks = [
        fetch_swagger(host, protocol),
        check_graphql(host, protocol),
        jwt_comprehensive_test(host, protocol),
        improved_rate_limit(host, 50, protocol),
    ]
    
    if aggressive:
        tasks.extend([
            idor_comprehensive_test(host, protocol),
            test_mass_assignment(host, protocol),
            test_api_injection(host, protocol),
        ])
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Unpack results
    swagger = results[0] if not isinstance(results[0], Exception) else {"exposed": False}
    graphql = results[1] if not isinstance(results[1], Exception) else {"vulnerable": False}
    jwt = results[2] if not isinstance(results[2], Exception) else {"findings": []}
    rate = results[3] if not isinstance(results[3], Exception) else {"vulnerable": True}
    
    if aggressive:
        idor = results[4] if not isinstance(results[4], Exception) else {"vulnerabilities": []}
        mass_assign = results[5] if not isinstance(results[5], Exception) else {"vulnerabilities": []}
        injection = results[6] if not isinstance(results[6], Exception) else {"vulnerabilities": []}
    else:
        idor = {"vulnerabilities": []}
        mass_assign = {"vulnerabilities": []}
        injection = {"vulnerabilities": []}
    
    # Compile findings
    findings = []
    vulnerabilities = []
    
    # Swagger findings
    if swagger.get("exposed"):
        findings.append({
            "type": "swagger_exposed",
            "location": swagger.get("url"),
            "impact": "API documentation exposed - enables easier enumeration and attack planning",
            "remediation": "Restrict public access or require authentication for API docs",
            "severity": "low",
            "endpoints_discovered": len(swagger.get("endpoints", []))
        })
        vulnerabilities.append({
            "title": "API Documentation Exposed",
            "severity": "low",
            "description": f"Found {len(swagger.get('endpoints', []))} API endpoints in documentation",
            "cve": None
        })
    
    # GraphQL findings
    if graphql.get("vulnerable"):
        for test in graphql.get("tests", []):
            if test.get("introspection_enabled"):
                findings.append({
                    "type": "graphql_introspection_enabled",
                    "location": test["endpoint"],
                    "impact": "Full schema disclosure aids attackers in crafting malicious queries",
                    "remediation": "Disable introspection in production or require authentication",
                    "severity": "medium",
                })
                vulnerabilities.append({
                    "title": "GraphQL Introspection Enabled",
                    "severity": "medium",
                    "description": "GraphQL schema fully accessible without authentication",
                    "cve": None
                })
            
            if test.get("batch_query_allowed") or test.get("deep_nesting_allowed"):
                vulnerabilities.append({
                    "title": "GraphQL DoS Vulnerability",
                    "severity": "high",
                    "description": "GraphQL endpoint vulnerable to resource exhaustion attacks",
                    "cve": None
                })
    
    # JWT findings
    for jwt_finding in jwt.get("findings", []):
        findings.append({
            "type": jwt_finding["type"],
            "severity": jwt_finding["severity"],
            "impact": jwt_finding.get("description", "JWT security issue"),
            "remediation": "Fix JWT implementation security"
        })
        if jwt_finding["severity"] in ["high", "critical"]:
            vulnerabilities.append({
                "title": f"JWT Security Issue: {jwt_finding['type']}",
                "severity": jwt_finding["severity"],
                "description": jwt_finding.get("description", ""),
                "cve": None
            })
    
    # IDOR findings
    for idor_vuln in idor.get("vulnerabilities", []):
        findings.append({
            "type": idor_vuln["type"],
            "location": idor_vuln["endpoint_pattern"],
            "impact": idor_vuln["description"],
            "remediation": "Implement proper authorization checks for object access",
            "severity": idor_vuln["severity"],
        })
        vulnerabilities.append({
            "title": f"IDOR Vulnerability: {idor_vuln['endpoint_pattern']}",
            "severity": idor_vuln["severity"],
            "description": idor_vuln["description"],
            "cve": None
        })
    
    # Mass Assignment findings
    for ma_vuln in mass_assign.get("vulnerabilities", []):
        findings.append({
            "type": "mass_assignment",
            "location": ma_vuln["endpoint"],
            "impact": "Attackers may inject admin roles or privileges",
            "remediation": "Whitelist allowed fields in API requests",
            "severity": "critical",
        })
        vulnerabilities.append({
            "title": f"Mass Assignment Vulnerability: {ma_vuln['endpoint']}",
            "severity": "critical",
            "description": ma_vuln["description"],
            "cve": None
        })
    
    # Injection findings
    for inj_vuln in injection.get("vulnerabilities", []):
        findings.append({
            "type": inj_vuln["type"],
            "location": inj_vuln["endpoint"],
            "impact": "Database injection may allow data theft or manipulation",
            "remediation": "Use parameterized queries and input validation",
            "severity": "critical",
        })
        vulnerabilities.append({
            "title": f"{inj_vuln['type'].upper()}: {inj_vuln['endpoint']}",
            "severity": "critical",
            "description": inj_vuln["description"],
            "cve": None
        })
    
    # Rate limit findings
    if rate.get("vulnerable"):
        findings.append({
            "type": "rate_limit_not_detected",
            "impact": "No rate limiting - vulnerable to brute force and DoS attacks",
            "remediation": "Implement rate limiting with IP and user-based policies",
            "severity": "medium",
        })
        vulnerabilities.append({
            "title": "No Rate Limiting Detected",
            "severity": "medium",
            "description": "API endpoints accept unlimited requests without throttling",
            "cve": None
        })
    
    # Summary
    critical_count = len([v for v in vulnerabilities if v["severity"] == "critical"])
    high_count = len([v for v in vulnerabilities if v["severity"] == "high"])
    
    print(f"[API-TEST] Complete: {len(vulnerabilities)} vulnerabilities found ({critical_count} CRITICAL, {high_count} HIGH)")
    
    return {
        "target": host,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "critical": critical_count,
            "high": high_count,
            "medium": len([v for v in vulnerabilities if v["severity"] == "medium"]),
            "low": len([v for v in vulnerabilities if v["severity"] == "low"]),
        },
        "details": {
            "swagger": swagger,
            "graphql": graphql,
            "jwt": jwt,
            "idor": idor,
            "mass_assignment": mass_assign,
            "injection": injection,
            "rate_limit": rate,
        }
    }
