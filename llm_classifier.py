import json
import asyncio
from typing import Optional, Dict, List
from groq import Groq

import config


class LLMClassifier:
    """Uses Groq's Llama 3.1 70B to intelligently classify APIs and endpoints."""
    
    def __init__(self):
        if not config.GROQ_API_KEY:
            self.enabled = False
            print("[!] Warning: GROQ_API_KEY not set. LLM features disabled.")
            return
        
        self.client = Groq(api_key=config.GROQ_API_KEY)
        self.enabled = True
        self.model = config.LLM_MODEL
    
    def classify_endpoint(self, url: str, method: str, response_status: int,
                         content_type: str, response_sample: Optional[str] = None,
                         headers: Optional[Dict] = None) -> Dict:
        """
        Use LLM to classify an endpoint's purpose, risk level, and attack surface.
        
        Returns:
            {
                "purpose": str,
                "type": str (REST_API, FORM, AUTH, STATIC, etc),
                "risk_level": str (CRITICAL, HIGH, MEDIUM, LOW),
                "requires_auth": bool,
                "interesting": bool,
                "reasoning": str,
                "recommendations": [str]
            }
        """
        if not self.enabled:
            return self._fallback_classify(url, method, response_status, content_type)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{
                    "role": "user",
                    "content": self._build_classification_prompt(
                        url, method, response_status, content_type, 
                        response_sample, headers
                    )
                }],
                temperature=0.3,  # Lower temp for more consistent classification
                max_tokens=500,
            )
            
            result_text = response.choices[0].message.content
            return self._parse_classification_response(result_text)
            
        except Exception as e:
            print(f"[X] LLM classification failed for {url}: {e}")
            return self._fallback_classify(url, method, response_status, content_type)
    
    def prioritize_attack_surface(self, endpoints: List[Dict]) -> List[Dict]:
        """
        Use LLM to prioritize which endpoints are most interesting for penetration testing.
        
        Returns endpoints sorted by priority with reasoning.
        """
        if not self.enabled or not endpoints:
            return self._fallback_prioritize(endpoints)
        
        try:
            # Sample high-value endpoints for LLM (limit to avoid token overload)
            sample = endpoints[:20] if len(endpoints) > 20 else endpoints
            
            prompt = f"""You are a penetration testing expert. Given these discovered endpoints, 
rank them by attack surface priority. Focus on:
1. Unauthenticated high-privilege operations
2. Information disclosure vectors
3. Business logic flaws
4. Data manipulation capabilities
5. Admin/internal endpoints

Endpoints:
{json.dumps([{
    'url': e.get('url'),
    'method': e.get('method'),
    'type': e.get('classification', {}).get('type'),
    'requires_auth': e.get('classification', {}).get('requires_auth'),
    'risk_level': e.get('classification', {}).get('risk_level'),
} for e in sample], indent=2)}

Return a JSON array with fields: url, priority (1-5, 5=highest), why, exploit_idea
"""
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=2000,
            )
            
            result_text = response.choices[0].message.content
            
            # Extract JSON from response
            try:
                json_start = result_text.find('[')
                json_end = result_text.rfind(']') + 1
                if json_start != -1 and json_end > json_start:
                    prioritized = json.loads(result_text[json_start:json_end])
                    return prioritized
            except json.JSONDecodeError:
                pass
            
            return self._fallback_prioritize(endpoints)
            
        except Exception as e:
            print(f"[X] LLM prioritization failed: {e}")
            return self._fallback_prioritize(endpoints)
    
    def _build_classification_prompt(self, url: str, method: str, status: int,
                                     content_type: str, response_sample: Optional[str],
                                     headers: Optional[Dict]) -> str:
        """Build classification prompt for LLM."""
        return f"""Classify this API endpoint as a JSON object with these fields:
- purpose: Brief description of what this endpoint does
- type: One of [REST_API, FORM, AUTH, STATIC_PAGE, ADMIN, INTERNAL, FILE_UPLOAD, REDIRECT, ERROR, UNKNOWN]
- risk_level: One of [CRITICAL, HIGH, MEDIUM, LOW, INFO]
- requires_auth: Boolean (true if likely requires authentication)
- interesting: Boolean (true if likely has security value to test)
- reasoning: 2-sentence explanation
- recommendations: Array of 2-3 testing strategies

Endpoint Details:
URL: {url}
Method: {method}
Status Code: {status}
Content-Type: {content_type}
Response Sample: {response_sample[:200] if response_sample else "N/A"}
Headers: {json.dumps(dict(headers) if headers else {{}}, indent=2)[:300]}

Respond with ONLY valid JSON, no markdown markers."""

    def _parse_classification_response(self, response_text: str) -> Dict:
        """Extract and parse JSON classification from LLM response."""
        try:
            # Extract JSON from response (handle markdown code blocks)
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]
            
            classification = json.loads(response_text.strip())
            
            # Validate required fields
            classification.setdefault('purpose', 'Unknown endpoint')
            classification.setdefault('type', 'UNKNOWN')
            classification.setdefault('risk_level', 'LOW')
            classification.setdefault('requires_auth', False)
            classification.setdefault('interesting', False)
            classification.setdefault('reasoning', '')
            classification.setdefault('recommendations', [])
            
            return classification
        except json.JSONDecodeError:
            return self._fallback_classify_result()
    
    def _fallback_classify(self, url: str, method: str, status: int, 
                          content_type: str) -> Dict:
        """Fallback classification when LLM is unavailable."""
        # Simple heuristic-based classification
        url_lower = url.lower()
        
        is_auth = any(x in url_lower for x in ['/login', '/register', '/auth', '/forgot'])
        is_admin = any(x in url_lower for x in ['/admin', '/sup3r', '/dashboard'])
        is_api = '/api' in url_lower
        is_static = any(x in content_type for x in ['text/html', 'text/css', 'text/javascript'])
        is_upload = any(x in url_lower for x in ['/upload', '/file', '/picture'])
        
        risk_level = 'CRITICAL' if is_admin else 'HIGH' if is_auth else 'MEDIUM' if is_api else 'LOW'
        
        endpoint_type = 'ADMIN' if is_admin else 'AUTH' if is_auth else 'FILE_UPLOAD' if is_upload else 'REST_API' if is_api else 'STATIC_PAGE'
        
        return {
            'purpose': f'{method} endpoint for {url_lower.split("/")[-1] or "root"}',
            'type': endpoint_type,
            'risk_level': risk_level,
            'requires_auth': status == 401 or status == 403,
            'interesting': status not in [404, 301, 302],
            'reasoning': f'Status {status}, heuristic classification',
            'recommendations': ['Test for common vulns', 'Analyze response patterns'],
        }
    
    def _fallback_classify_result(self) -> Dict:
        """Default classification result."""
        return {
            'purpose': 'Unknown',
            'type': 'UNKNOWN',
            'risk_level': 'LOW',
            'requires_auth': False,
            'interesting': False,
            'reasoning': 'Classification skipped',
            'recommendations': [],
        }
    
    def _fallback_prioritize(self, endpoints: List[Dict]) -> List[Dict]:
        """Simple heuristic prioritization."""
        def get_priority_score(ep: Dict) -> tuple:
            risk_map = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
            risk = risk_map.get(ep.get('classification', {}).get('risk_level', 'LOW'), 0)
            is_auth = 1 if ep.get('classification', {}).get('requires_auth') else 0
            interesting = 2 if ep.get('classification', {}).get('interesting') else 0
            return (risk, is_auth, interesting)
        
        sorted_eps = sorted(endpoints, key=get_priority_score, reverse=True)
        return sorted_eps[:20]
