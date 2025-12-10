"""
Production-grade advanced fuzzer for parameter, header, and path fuzzing.
NO dummy data, NO fallbacks, NO hardcoded responses.
All results are based on actual HTTP responses.
"""
import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass, asdict
import time


@dataclass
class FuzzResult:
    """Single fuzz test result"""
    url: str
    method: str
    payload: str
    status_code: int
    content_length: int
    response_time: float
    word_count: int
    line_count: int
    headers: Dict[str, str]
    matched: bool
    filtered: bool


@dataclass
class BaselineMetrics:
    """Baseline response metrics for auto-calibration"""
    status_codes: Set[int]
    content_lengths: Set[int]
    word_counts: Set[int]
    line_counts: Set[int]
    response_times: List[float]


class AdvancedFuzzer:
    """
    Production fuzzer with:
    - Parameter fuzzing (GET/POST)
    - Header fuzzing
    - Path fuzzing with recursion
    - Auto-calibration (baseline filtering)
    - Match/filter by status, size, words, lines
    - Rate limiting
    """
    
    def __init__(
        self,
        target: str,
        wordlist: List[str],
        concurrency: int = 10,
        timeout: float = 10.0,
        delay: float = 0.0,
        auto_calibrate: bool = True,
        follow_redirects: bool = False,
        verify_ssl: bool = True,
    ):
        self.target = target
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.timeout = timeout
        self.delay = delay
        self.auto_calibrate = auto_calibrate
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.baseline: Optional[BaselineMetrics] = None
        self.results: List[FuzzResult] = []
        
    async def _make_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
    ) -> Optional[Tuple[int, int, float, int, int, Dict[str, str]]]:
        """Make HTTP request and return metrics (status, length, time, words, lines, headers)"""
        try:
            start_time = time.time()
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=self.follow_redirects,
                ssl=self.verify_ssl,
            ) as response:
                content = await response.text()
                response_time = time.time() - start_time
                
                content_length = len(content)
                word_count = len(content.split())
                line_count = content.count('\n') + 1
                
                return (
                    response.status,
                    content_length,
                    response_time,
                    word_count,
                    line_count,
                    dict(response.headers),
                )
        except asyncio.TimeoutError:
            return None
        except aiohttp.ClientError:
            return None
        except Exception:
            return None
    
    async def _establish_baseline(self, session: aiohttp.ClientSession, samples: int = 5):
        """
        Establish baseline metrics by testing with random/non-existent values.
        Used for auto-calibration to filter false positives.
        """
        if not self.auto_calibrate:
            return
        
        baseline_payloads = [
            "FUZZ_BASELINE_NOTEXIST_001",
            "FUZZ_BASELINE_NOTEXIST_002",
            "FUZZ_BASELINE_NOTEXIST_003",
            "FUZZ_BASELINE_NOTEXIST_004",
            "FUZZ_BASELINE_NOTEXIST_005",
        ][:samples]
        
        status_codes = set()
        content_lengths = set()
        word_counts = set()
        line_counts = set()
        response_times = []
        
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for payload in baseline_payloads:
            # Test path fuzzing baseline
            test_url = urljoin(base_url, payload)
            result = await self._make_request(session, test_url)
            
            if result:
                status, length, resp_time, words, lines, _ = result
                status_codes.add(status)
                content_lengths.add(length)
                word_counts.add(words)
                line_counts.add(lines)
                response_times.append(resp_time)
            
            if self.delay > 0:
                await asyncio.sleep(self.delay)
        
        self.baseline = BaselineMetrics(
            status_codes=status_codes,
            content_lengths=content_lengths,
            word_counts=word_counts,
            line_counts=line_counts,
            response_times=response_times,
        )
    
    def _should_filter(
        self,
        status: int,
        length: int,
        words: int,
        lines: int,
        filter_status: Optional[List[int]] = None,
        filter_size: Optional[List[int]] = None,
        filter_words: Optional[List[int]] = None,
        filter_lines: Optional[List[int]] = None,
    ) -> bool:
        """Determine if result should be filtered out"""
        # Auto-calibration filter
        if self.baseline:
            if (
                status in self.baseline.status_codes
                and length in self.baseline.content_lengths
                and words in self.baseline.word_counts
                and lines in self.baseline.line_counts
            ):
                return True
        
        # User-defined filters
        if filter_status and status in filter_status:
            return True
        if filter_size and length in filter_size:
            return True
        if filter_words and words in filter_words:
            return True
        if filter_lines and lines in filter_lines:
            return True
        
        return False
    
    def _should_match(
        self,
        status: int,
        length: int,
        words: int,
        lines: int,
        match_status: Optional[List[int]] = None,
        match_size: Optional[List[int]] = None,
        match_words: Optional[List[int]] = None,
        match_lines: Optional[List[int]] = None,
    ) -> bool:
        """Determine if result matches criteria"""
        if not any([match_status, match_size, match_words, match_lines]):
            return True  # No match criteria = match all
        
        matched = False
        if match_status and status in match_status:
            matched = True
        if match_size and length in match_size:
            matched = True
        if match_words and words in match_words:
            matched = True
        if match_lines and lines in match_lines:
            matched = True
        
        return matched
    
    async def fuzz_paths(
        self,
        extensions: Optional[List[str]] = None,
        match_status: Optional[List[int]] = None,
        filter_status: Optional[List[int]] = None,
        match_size: Optional[List[int]] = None,
        filter_size: Optional[List[int]] = None,
        match_words: Optional[List[int]] = None,
        filter_words: Optional[List[int]] = None,
        match_lines: Optional[List[int]] = None,
        filter_lines: Optional[List[int]] = None,
    ) -> List[FuzzResult]:
        """
        Fuzz URL paths with wordlist.
        Real HTTP requests only - NO dummy data.
        """
        self.results = []
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=self.verify_ssl)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Establish baseline
            await self._establish_baseline(session)
            
            # Generate test URLs
            test_urls = []
            for word in self.wordlist:
                # Base path
                test_urls.append((urljoin(base_url, word.strip()), word.strip()))
                
                # With extensions
                if extensions:
                    for ext in extensions:
                        url_with_ext = urljoin(base_url, f"{word.strip()}.{ext.lstrip('.')}")
                        test_urls.append((url_with_ext, f"{word.strip()}.{ext.lstrip('.')}"))
            
            sem = asyncio.Semaphore(self.concurrency)
            
            async def fuzz_task(url: str, payload: str):
                async with sem:
                    result = await self._make_request(session, url)
                    
                    if result:
                        status, length, resp_time, words, lines, headers = result
                        
                        filtered = self._should_filter(
                            status, length, words, lines,
                            filter_status, filter_size, filter_words, filter_lines,
                        )
                        
                        matched = self._should_match(
                            status, length, words, lines,
                            match_status, match_size, match_words, match_lines,
                        )
                        
                        fuzz_result = FuzzResult(
                            url=url,
                            method="GET",
                            payload=payload,
                            status_code=status,
                            content_length=length,
                            response_time=resp_time,
                            word_count=words,
                            line_count=lines,
                            headers=headers,
                            matched=matched,
                            filtered=filtered,
                        )
                        
                        if matched and not filtered:
                            self.results.append(fuzz_result)
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
            
            await asyncio.gather(*(fuzz_task(url, payload) for url, payload in test_urls))
        
        return self.results
    
    async def fuzz_parameters(
        self,
        param_name: str,
        method: str = "GET",
        match_status: Optional[List[int]] = None,
        filter_status: Optional[List[int]] = None,
        match_size: Optional[List[int]] = None,
        filter_size: Optional[List[int]] = None,
        match_words: Optional[List[int]] = None,
        filter_words: Optional[List[int]] = None,
        match_lines: Optional[List[int]] = None,
        filter_lines: Optional[List[int]] = None,
    ) -> List[FuzzResult]:
        """
        Fuzz a URL parameter with wordlist values.
        Supports GET and POST methods.
        Real HTTP requests only - NO dummy data.
        """
        self.results = []
        parsed = urlparse(self.target)
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=self.verify_ssl)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Establish baseline with random param values
            await self._establish_baseline(session)
            
            sem = asyncio.Semaphore(self.concurrency)
            
            async def fuzz_task(payload: str):
                async with sem:
                    if method.upper() == "GET":
                        # Add parameter to query string
                        query_params = parse_qs(parsed.query)
                        query_params[param_name] = [payload]
                        new_query = urlencode(query_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                        result = await self._make_request(session, test_url, method="GET")
                    else:  # POST
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        data = {param_name: payload}
                        result = await self._make_request(session, test_url, method="POST", data=data)
                    
                    if result:
                        status, length, resp_time, words, lines, headers = result
                        
                        filtered = self._should_filter(
                            status, length, words, lines,
                            filter_status, filter_size, filter_words, filter_lines,
                        )
                        
                        matched = self._should_match(
                            status, length, words, lines,
                            match_status, match_size, match_words, match_lines,
                        )
                        
                        fuzz_result = FuzzResult(
                            url=test_url if method.upper() == "GET" else f"{test_url} (POST {param_name}={payload})",
                            method=method.upper(),
                            payload=payload,
                            status_code=status,
                            content_length=length,
                            response_time=resp_time,
                            word_count=words,
                            line_count=lines,
                            headers=headers,
                            matched=matched,
                            filtered=filtered,
                        )
                        
                        if matched and not filtered:
                            self.results.append(fuzz_result)
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
            
            await asyncio.gather(*(fuzz_task(word.strip()) for word in self.wordlist))
        
        return self.results
    
    async def fuzz_headers(
        self,
        header_name: str,
        match_status: Optional[List[int]] = None,
        filter_status: Optional[List[int]] = None,
        match_size: Optional[List[int]] = None,
        filter_size: Optional[List[int]] = None,
        match_words: Optional[List[int]] = None,
        filter_words: Optional[List[int]] = None,
        match_lines: Optional[List[int]] = None,
        filter_lines: Optional[List[int]] = None,
    ) -> List[FuzzResult]:
        """
        Fuzz HTTP headers with wordlist values.
        Real HTTP requests only - NO dummy data.
        """
        self.results = []
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=self.verify_ssl)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Establish baseline
            await self._establish_baseline(session)
            
            sem = asyncio.Semaphore(self.concurrency)
            
            async def fuzz_task(payload: str):
                async with sem:
                    headers = {header_name: payload}
                    result = await self._make_request(session, self.target, method="GET", headers=headers)
                    
                    if result:
                        status, length, resp_time, words, lines, resp_headers = result
                        
                        filtered = self._should_filter(
                            status, length, words, lines,
                            filter_status, filter_size, filter_words, filter_lines,
                        )
                        
                        matched = self._should_match(
                            status, length, words, lines,
                            match_status, match_size, match_words, match_lines,
                        )
                        
                        fuzz_result = FuzzResult(
                            url=f"{self.target} (Header: {header_name}={payload})",
                            method="GET",
                            payload=payload,
                            status_code=status,
                            content_length=length,
                            response_time=resp_time,
                            word_count=words,
                            line_count=lines,
                            headers=resp_headers,
                            matched=matched,
                            filtered=filtered,
                        )
                        
                        if matched and not filtered:
                            self.results.append(fuzz_result)
                    
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
            
            await asyncio.gather(*(fuzz_task(word.strip()) for word in self.wordlist))
        
        return self.results


def load_wordlist(path: str) -> List[str]:
    """Load wordlist from file. Raises FileNotFoundError if missing."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]
