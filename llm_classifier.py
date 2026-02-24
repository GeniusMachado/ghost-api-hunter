import json
import time
from typing import Optional, Dict, List
import google.genai as genai

import config


class LLMClassifier:
    """Uses Google Gemini API for intelligent API classification and prioritization."""
    
    def __init__(self):
        if not config.GEMINI_API_KEY:
            self.enabled = False
            print("[!] LLM disabled - add GEMINI_API_KEY to .env to enable")
            return
        
        genai.configure(api_key=config.GEMINI_API_KEY)
        self.client = genai.GenerativeModel(config.LLM_MODEL)
        self.enabled = True
        self.model = config.LLM_MODEL
    
    def classify_endpoint(self, url: str, method: str, response_status: int,
                         content_type: str, response_sample: Optional[str] = None,
                         headers: Optional[Dict] = None) -> Dict:
        """Classify endpoint for pentesting priority and risk assessment."""
        if not self.enabled:
            return self._fallback_classify(url, method, response_status, content_type)
        
        try:
            prompt = self._build_classification_prompt(
                url, method, response_status, content_type, 
                response_sample, headers
            )
            
            response = self.client.generate_content(prompt)
            result_text = response.text
            
            return self._parse_classification_response(result_text)
            
        except Exception as e:
            print(f"[X] Classification error: {e}")
            return self._fallback_classify(url, method, response_status, content_type)
    
    def prioritize_attack_surface(self, endpoints: List[Dict]) -> List[Dict]:
        """Rank endpoints by security testing importance."""
        if not self.enabled or not endpoints:
            return self._fallback_prioritize(endpoints)
        
        try:
            sample = endpoints[:20] if len(endpoints) > 20 else endpoints
            
            prompt = f"""You're a security researcher. Rank these endpoints by testing priority (1-5, 5=highest).
Consider: unauthenticated ops, admin endpoints, business logic, data manipulation, info disclosure.

Endpoints:
{json.dumps([{
    'url': e.get('url'),
    'method': e.get('method'),
    'type': e.get('classification', {}).get('type'),
    'requires_auth': e.get('classification', {}).get('requires_auth'),
    'risk_level': e.get('classification', {}).get('risk_level'),
} for e in sample], indent=2)}

Return ONLY JSON array: [{"url": "", "priority": 5, "why": "", "exploit_idea": ""}]"""
            
            response = self.client.generate_content(prompt)
            result_text = response.text
            
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
            print(f"[X] Prioritization error: {e}")
            return self._fallback_prioritize(endpoints)
    
    def _build_classification_prompt(self, url: str, method: str, status: int,
                                     content_type: str, response_sample: Optional[str],
                                     headers: Optional[Dict]) -> str:
        """Build prompt for LLM classification."""
        return f"""Classify endpoint. Return ONLY JSON:
- purpose: what it does
- type: [REST_API, FORM, AUTH, STATIC_PAGE, ADMIN, INTERNAL, FILE_UPLOAD, REDIRECT, ERROR, UNKNOWN]
- risk_level: [CRITICAL, HIGH, MEDIUM, LOW, INFO]
- requires_auth: bool
- interesting: bool (worth testing)
- reasoning: 2 sentences
- recommendations: [3 testing ideas]

URL: {url}
Method: {method}
Status: {status}
Content-Type: {content_type}
Response: {response_sample[:200] if response_sample else "N/A"}

JSON only:"""

    def _parse_classification_response(self, response_text: str) -> Dict:
        """Extract JSON classification from response."""
        try:
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]
            
            classification = json.loads(response_text.strip())
            
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
        """Heuristic-based classification when LLM unavailable."""
        url_lower = url.lower()
        
        is_auth = any(x in url_lower for x in ['/login', '/register', '/auth', '/forgot'])
        is_admin = any(x in url_lower for x in ['/admin', '/sup3r', '/dashboard'])
        is_api = '/api' in url_lower
        is_upload = any(x in url_lower for x in ['/upload', '/file', '/picture'])
        
        risk_level = 'CRITICAL' if is_admin else 'HIGH' if is_auth else 'MEDIUM' if is_api else 'LOW'
        endpoint_type = 'ADMIN' if is_admin else 'AUTH' if is_auth else 'FILE_UPLOAD' if is_upload else 'REST_API' if is_api else 'STATIC_PAGE'
        
        return {
            'purpose': f'{method} endpoint - {url_lower.split("/")[-1] or "root"}',
            'type': endpoint_type,
            'risk_level': risk_level,
            'requires_auth': status == 401 or status == 403,
            'interesting': status not in [404, 301, 302],
            'reasoning': f'Based on status {status} and URL patterns',
            'recommendations': ['Test with common payloads', 'Check auth bypass', 'Analyze response'],
        }
    
    def _fallback_classify_result(self) -> Dict:
        """Default result when parsing fails."""
        return {
            'purpose': 'Unknown',
            'type': 'UNKNOWN',
            'risk_level': 'LOW',
            'requires_auth': False,
            'interesting': False,
            'reasoning': 'Unable to classify',
            'recommendations': [],
        }
    
    def _fallback_prioritize(self, endpoints: List[Dict]) -> List[Dict]:
        """Sort endpoints by risk level."""
        def score(ep: Dict) -> tuple:
            risk_weights = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
            risk = risk_weights.get(ep.get('classification', {}).get('risk_level', 'LOW'), 0)
            needs_auth = 0 if ep.get('classification', {}).get('requires_auth') else 1
            is_interesting = 1 if ep.get('classification', {}).get('interesting') else 0
            return (risk, needs_auth, is_interesting)
        
        sorted_eps = sorted(endpoints, key=score, reverse=True)
        return sorted_eps[:20]
