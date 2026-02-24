import asyncio
import json
import re
import time
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
from tqdm import tqdm
from tenacity import retry, stop_after_attempt, wait_exponential

import config
from llm_classifier import LLMClassifier


class APIHunter:
    """Discovers and classifies APIs on a target domain."""
    
    def __init__(self, target: str, llm_classifier: Optional[LLMClassifier] = None):
        self.target = target.rstrip('/')
        self.domain = urlparse(target).netloc
        self.classifier = llm_classifier or LLMClassifier()
        
        self.discovered_endpoints: List[Dict] = []
        self.visited_urls: Set[str] = set()
        self.failed_urls: Dict[str, str] = {}
        
        # HTTP client configuration
        self.timeout = httpx.Timeout(config.REQUEST_TIMEOUT)
        self.client: Optional[httpx.AsyncClient] = None
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'unique_endpoints': 0,
            'start_time': None,
            'end_time': None,
        }
    
    async def discover(self) -> List[Dict]:
        """Run full discovery pipeline."""
        print(f"\n[*] Starting API discovery for {self.target}\n")
        self.stats['start_time'] = time.time()
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            self.client = client
            
            # Phase 1: Probe common endpoints
            print("[*] Phase 1: Probing common endpoints...")
            await self._probe_common_endpoints()
            
            # Phase 2: Extract endpoints from responses
            print("[*] Phase 2: Parsing responses for endpoints...")
            await self._parse_responses()
            
            # Phase 3: Crawl HTML/JavaScript
            print("[*] Phase 3: Crawling HTML and JavaScript...")
            await self._crawl_html()
            
            # Phase 4: OpenAPI/Swagger detection
            print("[*] Phase 4: Detecting OpenAPI/Swagger specs...")
            await self._detect_openapi()
            
            # Phase 5: Parse OpenAPI if found
            print("[*] Phase 5: Parsing OpenAPI specifications...")
            await self._parse_openapi_specs()
            
            # Phase 6: LLM classification
            print("[*] Phase 6: Classifying endpoints with LLM...")
            self._classify_endpoints()
            
            # Phase 7: Prioritization
            print("[*] Phase 7: Prioritizing attack surface...")
            self.discovered_endpoints = self._prioritize_endpoints()
        
        self.stats['end_time'] = time.time()
        self.stats['unique_endpoints'] = len(self.discovered_endpoints)
        
        return self.discovered_endpoints
    
    async def _probe_common_endpoints(self) -> None:
        """Probe common endpoints to map the API surface."""
        tasks = [
            self._probe_endpoint(endpoint)
            for endpoint in config.COMMON_ENDPOINTS
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for endpoint, result in zip(config.COMMON_ENDPOINTS, results):
            if isinstance(result, Exception):
                continue
            if result:
                self.discovered_endpoints.append(result)
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _probe_endpoint(self, endpoint: str) -> Optional[Dict]:
        """Probe a single endpoint."""
        url = urljoin(self.target, endpoint)
        
        if url in self.visited_urls:
            return None
        
        self.visited_urls.add(url)
        await asyncio.sleep(config.RATE_LIMIT_DELAY)
        
        try:
            response = await self.client.get(url, follow_redirects=True)
            self.stats['total_requests'] += 1
            
            if response.status_code != 404:
                self.stats['successful_requests'] += 1
                return self._create_endpoint_record(url, response, 'GET')
            
        except httpx.TimeoutException:
            self.failed_urls[url] = "Timeout"
            self.stats['failed_requests'] += 1
        except Exception as e:
            self.failed_urls[url] = str(e)
            self.stats['failed_requests'] += 1
        
        return None
    
    async def _parse_responses(self) -> None:
        """Extract endpoints from HTML responses and links."""
        urls_to_parse = [ep['url'] for ep in self.discovered_endpoints]
        
        tasks = [self._extract_from_url(url) for url in urls_to_parse[:10]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                self.discovered_endpoints.extend(result)
    
    async def _extract_from_url(self, url: str) -> List[Dict]:
        """Extract links and endpoints from a URL."""
        new_endpoints = []
        await asyncio.sleep(config.RATE_LIMIT_DELAY)
        
        try:
            response = await self.client.get(url)
            if response.status_code == 200:
                # Parse HTML
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                for link in soup.find_all(['a', 'link']):
                    href = link.get('href', '')
                    if href and (href.startswith('/') or self.domain in href):
                        new_url = urljoin(self.target, href)
                        if new_url not in self.visited_urls:
                            new_endpoints.append(
                                self._create_endpoint_record(new_url, response, 'GET')
                            )
                
                # Extract form endpoints
                for form in soup.find_all('form'):
                    method = form.get('method', 'GET').upper()
                    action = form.get('action', '')
                    form_url = urljoin(self.target, action) if action else url
                    
                    if form_url not in self.visited_urls:
                        new_endpoints.append(
                            self._create_endpoint_record(form_url, response, method)
                        )
                
                # Extract JavaScript URLs (simple regex)
                js_urls = re.findall(r'["\']([/\w\-\.]+(?:api|endpoint|v\d+)[/\w\-\.]*)["\']',
                                    response.text)
                for js_url in js_urls:
                    full_url = urljoin(self.target, js_url)
                    if full_url not in self.visited_urls:
                        new_endpoints.append(
                            self._create_endpoint_record(full_url, response, 'GET')
                        )
        
        except Exception as e:
            pass
        
        return new_endpoints
    
    async def _crawl_html(self) -> None:
        """Crawl HTML pages for additional endpoints."""
        html_endpoints = [
            ep for ep in self.discovered_endpoints
            if 'text/html' in ep.get('content_type', '')
        ]
        
        for ep in html_endpoints[:5]:  # Limit crawl depth
            await self._extract_from_url(ep['url'])
    
    async def _detect_openapi(self) -> None:
        """Detect OpenAPI/Swagger specifications."""
        swagger_paths = [
            '/swagger.json', '/openapi.json', '/api/openapi.json',
            '/api/docs/swagger.json', '/static/openapi.json',
            '/api/v1/swagger.json', '/docs/swagger.json'
        ]
        
        tasks = [self._check_openapi_path(path) for path in swagger_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for path, spec in zip(swagger_paths, results):
            if isinstance(spec, dict):
                self.discovered_endpoints.append({
                    'url': urljoin(self.target, path),
                    'method': 'GET',
                    'status_code': 200,
                    'content_type': 'application/json',
                    'type': 'OPENAPI_SPEC',
                    'spec': spec,
                })
    
    async def _check_openapi_path(self, path: str) -> Optional[Dict]:
        """Check if a path contains OpenAPI spec."""
        url = urljoin(self.target, path)
        await asyncio.sleep(config.RATE_LIMIT_DELAY)
        
        try:
            response = await self.client.get(url)
            if response.status_code == 200:
                try:
                    return response.json()
                except:
                    pass
        except:
            pass
        
        return None
    
    async def _parse_openapi_specs(self) -> None:
        """Extract endpoints from OpenAPI specifications."""
        for ep in self.discovered_endpoints:
            if ep.get('type') == 'OPENAPI_SPEC' and 'spec' in ep:
                spec = ep['spec']
                
                # Extract paths from OpenAPI
                paths = spec.get('paths', {})
                for path, methods in paths.items():
                    for method in methods:
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                            endpoint_url = urljoin(self.target, path)
                            if endpoint_url not in self.visited_urls:
                                self.discovered_endpoints.append({
                                    'url': endpoint_url,
                                    'method': method.upper(),
                                    'status_code': 200,
                                    'content_type': 'application/json',
                                    'source': 'openapi_spec',
                                    'operation_id': methods[method].get('operationId'),
                                    'description': methods[method].get('summary', ''),
                                    'tags': methods[method].get('tags', []),
                                })
    
    def _classify_endpoints(self) -> None:
        """Classify each endpoint using LLM."""
        print(f"[*] Classifying {len(self.discovered_endpoints)} endpoints...\n")
        
        for ep in tqdm(self.discovered_endpoints, desc="Classifying"):
            if 'classification' not in ep:
                classification = self.classifier.classify_endpoint(
                    url=ep['url'],
                    method=ep.get('method', 'GET'),
                    response_status=ep.get('status_code', 200),
                    content_type=ep.get('content_type', 'text/html'),
                    response_sample=ep.get('response_sample'),
                    headers=ep.get('response_headers'),
                )
                ep['classification'] = classification
    
    def _prioritize_endpoints(self) -> List[Dict]:
        """Prioritize endpoints by attack surface."""
        print("\n[*] Using LLM to prioritize attack surface...")
        
        prioritized = self.classifier.prioritize_attack_surface(self.discovered_endpoints)
        
        if prioritized and isinstance(prioritized, list):
            # Merge LLM priority into endpoints
            for item in prioritized:
                for ep in self.discovered_endpoints:
                    if ep['url'] == item.get('url'):
                        ep['priority'] = item.get('priority', 3)
                        ep['exploit_idea'] = item.get('exploit_idea', '')
                        ep['why_important'] = item.get('why', '')
                        break
        
        # Sort by priority
        return sorted(
            self.discovered_endpoints,
            key=lambda x: (
                -x.get('priority', 0),
                -{'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2}.get(
                    x.get('classification', {}).get('risk_level', 'LOW'), 0),
                x.get('url', '')
            ),
            reverse=True
        )
    
    def _create_endpoint_record(self, url: str, response: httpx.Response, method: str) -> Dict:
        """Create a standardized endpoint record."""
        content_type = response.headers.get('content-type', 'unknown')
        response_sample = response.text[:500] if response.text else ""
        
        return {
            'url': url,
            'method': method,
            'status_code': response.status_code,
            'content_type': content_type,
            'response_headers': dict(response.headers),
            'response_sample': response_sample,
            'source': 'probe',
        }
    
    def get_summary(self) -> Dict:
        """Get discovery session summary."""
        return {
            'target': self.target,
            'duration_seconds': self.stats['end_time'] - self.stats['start_time'],
            'total_endpoints': len(self.discovered_endpoints),
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'endpoints_by_risk': self._group_by_risk(),
            'endpoints_by_type': self._group_by_type(),
        }
    
    def _group_by_risk(self) -> Dict[str, int]:
        """Count endpoints by risk level."""
        risk_counts = {}
        for ep in self.discovered_endpoints:
            risk = ep.get('classification', {}).get('risk_level', 'UNKNOWN')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        return risk_counts
    
    def _group_by_type(self) -> Dict[str, int]:
        """Count endpoints by type."""
        type_counts = {}
        for ep in self.discovered_endpoints:
            endpoint_type = ep.get('classification', {}).get('type', 'UNKNOWN')
            type_counts[endpoint_type] = type_counts.get(endpoint_type, 0) + 1
        return type_counts
