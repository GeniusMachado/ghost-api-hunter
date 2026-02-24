# Deployment Guide: Scaling to 50+ Microservices

This document outlines how Ghost API Hunter can be deployed and scaled within Assail's infrastructure for autonomous reconnaissance across large distributed systems.

## Architecture Integration with Assail Platform

### Current State (Single Machine)
```
CLI (main.py)
  ├─ APIHunter (asyncio)
  ├─ LLMClassifier (Groq)
  └─ ReportGenerator
```

### Production State (Kubernetes)
```
API Gateway (FastAPI)
  └─ Microservices (50+)
      ├─ ReconService (parallel hunters)
      ├─ ClassificationService (LLM pool)
      ├─ PrioritizationService (Kafka queue)
      ├─ ResultStore (PostgreSQL)
      └─ ReportingService (async generation)
```

## Deployment Scenarios

### Scenario 1: Internal Network Scanning (SOCKS5 Agents)

**Goal:** Discover APIs across internal corporate networks without direct access

**Architecture:**
```
┌─────────────────────────────────────────────────────┐
│ Assail Platform (Internet-facing)                   │
│  └─ Orchestrator (coordinates work)                │
└──────────────┬──────────────────────────────────────┘
               │ Deploy agents
       ┌───────┴───────┬───────────┐
       │               │           │
    ┌──▼──┐         ┌──▼──┐    ┌──▼──┐
    │Agent│         │Agent│    │Agent│
    │ Pod │         │ Pod │    │ Pod │
    └──┬──┘         └──┬──┘    └──┬──┘
       │ Tunnel       │ Tunnel    │ Tunnel
    [Internal A]   [Internal B]  [Internal C]
       ├─ Micro 1     ├─ API Srv  ├─ Payment API
       ├─ Micro 2     └─ DB       └─ Auth Srv
       └─ Micro 3
```

**Implementation:**
```python
# agent.py - deployed on internal network
from api_hunter import APIHunter

class RemoteAgent:
    def __init__(self, socks5_proxy="socks5://127.0.0.1:1080"):
        # Configure httpx client with SOCKS5 tunneling
        self.proxy = socks5_proxy
        self.hunter = None
    
    async def discover_internal_target(self, target_url):
        # All traffic tunneled through SOCKS5 proxy
        client = httpx.AsyncClient(
            proxy=self.proxy,
            timeout=20
        )
        self.hunter = APIHunter(target_url, client=client)
        return await self.hunter.discover()
```

**Deployment (Helm chart):**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ghost-api-agent
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: agent
        image: assail/ghost-api-agent:latest
        env:
        - name: ORCHESTRATOR_URL
          value: "https://platform.assail.internal"
        - name: SOCKS5_GATEWAY
          value: "socks5://gateway:1080"
        - name: GROQ_API_KEY
          valueFrom:
            secretKeyRef:
              name: llm-secrets
              key: groq-key
```

### Scenario 2: Scaling Across Kubernetes Cluster

**Goal:** Scan 50+ internal microservices in parallel without overwhelming any single target

**Kafka-based Queue:**
```python
# producer.py - Enqueues discovery tasks
async def schedule_microservice_scans():
    targets = await get_internal_microservices()  # Returns 50+ URLs
    
    for target in targets:
        await kafka.produce(
            "discovery.tasks",
            {
                "target": target["url"],
                "priority": target.get("priority", "MEDIUM"),
                "max_concurrent": 3,
                "timeout": 15
            }
        )

# consumer.py - Workers execute discovery
async def discovery_worker():
    async for message in kafka.consumer("discovery.tasks"):
        task = message.value
        hunter = APIHunter(
            target=task["target"],
            max_concurrent=task["max_concurrent"]
        )
        results = await hunter.discover()
        
        # Store results
        await postgres_store(results)
        
        # Trigger classification pipeline
        await kafka.produce("classification.tasks", results)
```

**Elasticsearch Integration for Results:**
```python
# Store discoveryresults for quick querying
async def index_endpoints(endpoints, target, timestamp):
    bulk_actions = []
    
    for ep in endpoints:
        bulk_actions.append({
            "_index": "api-endpoints",
            "_id": f"{target}:{ep['url']}",
            "_source": {
                "target": target,
                "url": ep['url'],
                "method": ep['method'],
                "risk_level": ep['classification']['risk_level'],
                "type": ep['classification']['type'],
                "discovered_at": timestamp,
                "tags": ep['classification'].get('tags', []),
                "exploit_idea": ep.get('exploit_idea', ''),
            }
        })
    
    await elasticsearch.bulk(bulk_actions)

# Kibana dashboard: Quick view of critical endpoints across all services
# Query: risk_level:"CRITICAL" AND discovered_at:>now-7d
```

### Scenario 3: Continuous Learning (Self-Improving)

**Goal:** Each discovery run improves future targeting through pattern learning

**Database Schema:**
```sql
-- Track endpoint patterns across targets
CREATE TABLE endpoint_patterns (
    id UUID PRIMARY KEY,
    domain VARCHAR,
    path_regex VARCHAR,
    method VARCHAR,
    risk_level VARCHAR,
    frequency INT,
    created_at TIMESTAMP,
    last_seen TIMESTAMP,
    INDEX (domain, path_regex)
);

-- Track discovery metrics
CREATE TABLE discovery_runs (
    id UUID PRIMARY KEY,
    target VARCHAR,
    endpoints_found INT,
    critical_count INT,
    duration_seconds FLOAT,
    efficiency_ratio FLOAT,        -- endpoints / requests
    run_strategy VARCHAR,          -- which phases used
    created_at TIMESTAMP,
    INDEX (target, created_at)
);

-- AI classification feedback loop
CREATE TABLE endpoint_classifications (
    id UUID PRIMARY KEY,
    endpoint_url VARCHAR,
    llm_classification JSONB,
    human_verification JSONB,      -- pentester feedback
    accuracy_score FLOAT,          -- 0-1 rating
    created_at TIMESTAMP,
    verified_at TIMESTAMP
);
```

**Learning Loop:**
```python
class SelfImprovingHunter:
    def __init__(self):
        self.db = AsyncPostgres()
        self.learned_patterns = {}
    
    async def initialize(self):
        # Load patterns from previous runs
        patterns = await self.db.query("""
            SELECT path_regex, risk_level, frequency
            FROM endpoint_patterns
            WHERE domain ILIKE %s
            ORDER BY frequency DESC
            LIMIT 100
        """, [self.target_domain])
        
        self.learned_patterns = {p['path_regex']: p for p in patterns}
    
    async def discover(self, target):
        # Phase 1-5: Standard discovery...
        
        # Phase 6: PRIORITY LEARNED PATTERNS
        learned_endpoints = await self._probe_learned_patterns()
        self.discovered_endpoints.extend(learned_endpoints)
        
        # At end, store patterns for future runs
        for ep in self.discovered_endpoints:
            await self._record_pattern(ep)
    
    async def _probe_learned_patterns(self):
        """Probe high-probability patterns from prior runs"""
        discovered = []
        
        for pattern, metadata in self.learned_patterns.items():
            # Generate URLs from regex patterns
            test_urls = self._generate_from_pattern(pattern)
            
            for url in test_urls:
                response = await self.client.get(url)
                if response.status_code != 404:
                    discovered.append(self._create_endpoint_record(url, response))
        
        return discovered
    
    async def _record_pattern(self, endpoint):
        """Store discovered pattern for future use"""
        path_regex = self._extract_path_pattern(endpoint['url'])
        risk_level = endpoint['classification']['risk_level']
        
        await self.db.query("""
            INSERT INTO endpoint_patterns 
            (domain, path_regex, method, risk_level, frequency, created_at, last_seen)
            VALUES (%s, %s, %s, %s, 1, NOW(), NOW())
            ON CONFLICT (domain, path_regex, method)
            DO UPDATE SET frequency = frequency + 1, last_seen = NOW()
        """, [self.target_domain, path_regex, endpoint['method'], risk_level])
```

### Scenario 4: Pentester Feedback Loop

**Goal:** Pentester feedback trains the LLM classifier to improve over time

```python
class AdaptiveClassifier:
    def __init__(self):
        self.llm = Groq()
        self.db = AsyncPostgres()
        self.human_feedback_queue = []
    
    async def classify_with_feedback(self, endpoint):
        """Classify using history of pentester corrections"""
        
        # 1. Get previous classifications for similar endpoints
        history = await self.db.query("""
            SELECT llm_classification, human_verification, accuracy_score
            FROM endpoint_classifications
            WHERE endpoint_url ILIKE %s || '%'
            ORDER BY verified_at DESC
            LIMIT 5
        """, [self._get_path_prefix(endpoint['url'])])
        
        # 2. Build prompt with examples of corrected classifications
        prompt = self._build_feedback_prompt(endpoint, history)
        
        # 3. Get LLM classification with improved accuracy
        classification = await self.llm.classify(prompt)
        
        # 4. Store for feedback tracking
        await self.db.query("""
            INSERT INTO endpoint_classifications 
            (endpoint_url, llm_classification, created_at)
            VALUES (%s, %s, NOW())
        """, [endpoint['url'], json.dumps(classification)])
        
        return classification
    
    async def record_pentester_correction(self, endpoint_url, corrected_classification):
        """Pentester says: 'This is actually HIGH, not MEDIUM'"""
        
        await self.db.query("""
            UPDATE endpoint_classifications
            SET human_verification = %s,
                accuracy_score = CASE
                    WHEN llm_classification->'risk_level' = %s THEN 1.0
                    WHEN llm_classification->'risk_level' IN (SELECT ...) THEN 0.5
                    ELSE 0.0
                END,
                verified_at = NOW()
            WHERE endpoint_url = %s
            ORDER BY created_at DESC
            LIMIT 1
        """, [json.dumps(corrected_classification), 
              corrected_classification.get('risk_level'),
              endpoint_url])
```

## Monitoring & Observability

### Prometheus Metrics
```python
from prometheus_client import Counter, Histogram, Gauge

# Metrics
discoveries_total = Counter(
    'discoveries_total',
    'Total discovery runs',
    ['target_domain', 'status']
)

endpoints_discovered = Gauge(
    'endpoints_discovered',
    'Current endpoint count',
    ['target_domain', 'risk_level']
)

discovery_duration_seconds = Histogram(
    'discovery_duration_seconds',
    'Time to complete discovery',
    ['target_domain']
)

classification_accuracy = Gauge(
    'classification_accuracy',
    'LLM classification accuracy vs human feedback',
    ['classifier_version']
)
```

### Logging  
```python
import structlog

logger = structlog.get_logger()

logger.info("discovery_started", target=target, phase="probe_common")
logger.warning("slow_endpoint", url=url, response_time_ms=2500)
logger.error("discovery_failed", target=target, reason="timeout")
logger.info("critical_finding", url=admin_endpoint, risk="CRITICAL")
```

## Performance at Scale

### Benchmarking Single Service
- **Requests:** 38 HTTP requests
- **Speed:** 8.9 seconds
- **Memory:** ~80 MB
- **Endpoints discovered:** 55

### Projected 50-Microservice Deployment
```
Sequential (no parallelism):    50 × 8.9s = 445s (7.4 minutes)
Parallel (5 agents):            50 × 8.9s / 5 = 89s (1.5 minutes)
Parallel + Learned Patterns:    ~45s (1-2s per service with cached patterns)
```

### Cost Analysis (AWS)
- **Single run:** 38 API requests × $0.001/req = $0.04
- **Monthly (1 target/day):** ~$1.20
- **Enterprise (50 targets, 2x daily):** ~$120/month
- **Groq LLM:** $0.29 per second (~$0.5 per run avg) = $30/month for 50 targets

## Security Considerations

### Agent Isolation
- Agents run in separate Kubernetes pods
- Network policies restrict agent-to-agent communication
- SOCKS5 proxy enforces rate limiting per agent
- Agents cannot access other agents' configuration

### Credential Management
- API keys stored in Kubernetes Secrets (encrypted at rest)
- Rotated weekly via HashiCorp Vault integration
- Agent pods mount secrets as read-only volumes
- No credentials logged or stored in results

### Results Encryption
- Discovery results encrypted in transit (TLS 1.3)
- Stored encrypted in PostgreSQL (pgcrypt)
- Elasticsearch indexes also encrypted
- Access controlled via RBAC

## Migration from Single-Tool to Platform

**Week 1:** Deploy Ghost API Hunter as standalone service
```bash
docker build -t ghost-api-hunter .
docker run -e GROQ_API_KEY=$KEY ghost-api-hunter vulnbank.org
```

**Week 2:** Integrate with platform API
```python
POST /api/discovery/submit
{
  "target": "https://internal-service.corp",
  "priority": "HIGH",
  "callback_url": "https://platform/webhooks/discovery/{run_id}"
}
```

**Week 3:** Deploy Kubernetes workers
```bash
helm install ghost-api-hunters ./helm-chart \
  --set replicas=5 \
  --set orchestrator_url=https://platform
```

**Week 4:** Enable learning loop and feedback integration

## Troubleshooting Deployment

### High Memory Usage
- Reduce `MAX_CONCURRENT_REQUESTS` in config
- Lower resource limits in Kubernetes deployment
- Implement response streaming instead of buffering

### Slow Discovery on Large APIs
- Increase number of agent replicas
- Enable pattern caching (learning loop)
- Pre-filter targets by known unsafe patterns

### LLM API Timeouts
- Implement exponential backoff
- Fall back to heuristic classification
- Queue classification for async processing

---

**Next Phase:** Integrate with Assail's exploit orchestration system to automatically test discovered CRITICAL endpoints
