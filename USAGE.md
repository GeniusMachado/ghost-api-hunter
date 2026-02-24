# Quick Start Guide

## Installation (2 minutes)

```bash
# 1. Navigate to project
cd letskillit

# 2. Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment template
cp .env.example .env

# 5. [OPTIONAL] Add LLM API Key for Llama 3.1 70B classification
# Get free key at https://console.groq.com
# Then edit .env and add: GROQ_API_KEY=your_key_here
```

## Running Discovery

### Quick Run (Default Target: vulnbank.org)
```bash
python main.py
```

### Custom Target
```bash
python main.py --target https://api.example.com
```

### Output Control
```bash
# JSON only
python main.py --format json

# Markdown only  
python main.py --format markdown

# Both (default)
python main.py --format both
```

### Without LLM (Offline Mode)
```bash
python main.py --no-llm
```

## Output Files

Discovery generates two report formats in the `output/` directory:

### JSON Report (`api_discovery_*.json`)
Complete discovery data including:
- All 55+ endpoints with metadata
- Classification for each endpoint (type, risk level, exploit ideas)
- Summary statistics and risk distribution
- Programmatic parsing-friendly format

### Markdown Report (`api_discovery_*.md`)
Human-readable format including:
- Executive summary
- Risk distribution charts
- Critical finding details
- Full endpoint table
- Great for quick briefings

## Example Results

From vulnbank.org discovery run:

```
[+] Summary:
    Total Endpoints: 55
    Duration: 8.9 seconds
    Critical Findings: 4
    High Risk: 6

[*] Top Findings:
    1. [CRITICAL] POST /admin/delete_account/{user_id}
    2. [CRITICAL] POST /admin/create_admin  
    3. [CRITICAL] POST /admin/approve_loan/{loan_id}
    4. [HIGH] POST /api/ai/chat/anonymous (Prompt injection)
```

## Troubleshooting

### Module not found errors
```bash
# Make sure you've activated the virtual environment:
source venv/bin/activate  # (or: venv\Scripts\activate on Windows)

# Then install dependencies:
pip install -r requirements.txt
```

### Unicode encoding errors (Windows)
The tool should auto-handle this, but if you see encoding errors:
```bash
# Run with UTF-8 encoding enabled:
$env:PYTHONIOENCODING="utf-8"
python main.py
```

### Timeout errors against slow targets
Increase timeout in `.env`:
```env
REQUEST_TIMEOUT=30  # seconds
RATE_LIMIT_DELAY=1   # seconds between requests
```

### Getting too many false positives
Lower rate limit delay to probe less aggressively:
```env
RATE_LIMIT_DELAY=0.2  # Faster probing
```

## Understanding the Reports

### Risk Levels
- **CRITICAL:** Unauthenticated access to sensitive operations (admin, financial)
- **HIGH:** Potential privilege escalation, business logic flaws
- **MEDIUM:** Typical API endpoints with normal vulns (injection, BOLA, etc.)
- **LOW:** Static content, non-sensitive informational endpoints

### Endpoint Types
- **REST_API:** Standard RESTful API endpoint
- **AUTH:** Login, registration, authentication endpoints
- **ADMIN:** Administrative panel or privileged operations
- **FILE_UPLOAD:** File upload or form submission endpoints
- **STATIC_PAGE:** HTML, CSS, JS static content

### What to Test First
Focus on endpoints marked CRITICAL or HIGH risk first, then:
1. Unauthenticated endpoints (require 0 credentials to access)
2. Admin-adjacent endpoints (may have auth bypass)
3. Financial operations (highest business impact)
4. AI/LLM integration points (emerging attack surface)

## Advanced Usage

### Debug Mode
```bash
# Print verbose discovery information
python -c "import logging; logging.basicConfig(level=logging.DEBUG)" && python main.py
```

### Analyze Previous Results
```bash
python -c "
import json
data = json.load(open('results/api_discovery_latest.json'))
critical = [ep for ep in data['endpoints'] if ep['classification']['risk_level'] == 'CRITICAL']
for ep in critical:
    print(f\"{ep['method']} {ep['url']}\")
"
```

## Next Steps

1. **Extend the discovery:** Modify `config.py` to add custom endpoints
2. **Integrate with Burp:** Export results to Burp Suite for manual testing
3. **Automate exploitation:** Feed critical endpoints to automated scanner
4. **Scale it:** Deploy as microservice for continuous target reconnaissance
5. **Learn from results:** Run against multiple targets and analyze patterns

## Resources

- **Challenge Details:** See WRITEUP.md for full technical analysis
- **Project Docs:** See README.md for architecture and design decisions
- **API Reference:** vulnbank.org/api/docs

## Support

For issues:
1. Check that all dependencies are installed: `pip list | grep -E "httpx|groq|beautifulsoup"`
2. Verify target is accessible: `curl https://your-target.com`
3. Check that GROQ_API_KEY is set if using LLM: `echo $GROQ_API_KEY`
4. Review .env configuration matches your target

---

**Ready to discover APIs?** Run: `python main.py`
