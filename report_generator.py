import json
import os
from datetime import datetime
from typing import List, Dict
import config


class ReportGenerator:
    """Generate reports of API discovery findings."""
    
    def __init__(self, output_dir: str = config.OUTPUT_DIR):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def save_json_report(self, endpoints: List[Dict], summary: Dict, filename: str = None) -> str:
        """Save findings as JSON."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"api_discovery_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': summary,
            'endpoints': endpoints,
            'critical_findings': self._extract_critical(endpoints),
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filepath
    
    def save_markdown_report(self, endpoints: List[Dict], summary: Dict, 
                            filename: str = None) -> str:
        """Save findings as Markdown."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"api_discovery_{timestamp}.md"
        
        filepath = os.path.join(self.output_dir, filename)
        
        content = self._generate_markdown(endpoints, summary)
        
        with open(filepath, 'w', encoding='utf-8', errors='replace') as f:
            f.write(content)
        
        return filepath
    
    def _generate_markdown(self, endpoints: List[Dict], summary: Dict) -> str:
        """Generate markdown report content."""
        lines = []
        
        lines.append("# API Discovery Report")
        lines.append(f"**Target:** {summary['target']}")
        lines.append(f"**Timestamp:** {datetime.now().isoformat()}")
        lines.append(f"**Duration:** {summary['duration_seconds']:.1f}s\n")
        
        lines.append("## Summary")
        lines.append(f"- **Total Endpoints:** {summary['total_endpoints']}")
        lines.append(f"- **Total Requests:** {summary['total_requests']}")
        lines.append(f"- **Success Rate:** {(summary['successful_requests'] / max(1, summary['total_requests']) * 100):.1f}%\n")
        
        lines.append("### Endpoints by Risk Level")
        for risk, count in sorted(summary['endpoints_by_risk'].items(), reverse=True):
            lines.append(f"- **{risk}:** {count}")
        
        lines.append("\n### Endpoints by Type")
        for ep_type, count in sorted(summary['endpoints_by_type'].items()):
            lines.append(f"- **{ep_type}:** {count}")
        
        lines.append("\n## Critical & High-Risk Endpoints\n")
        critical = self._extract_critical(endpoints)
        if critical:
            for ep in critical[:20]:
                lines.append(f"### {ep['method']} {ep['url']}")
                lines.append(f"**Risk Level:** {ep.get('classification', {}).get('risk_level', 'UNKNOWN')}")
                lines.append(f"**Type:** {ep.get('classification', {}).get('type', 'UNKNOWN')}")
                lines.append(f"**Purpose:** {ep.get('classification', {}).get('purpose', 'Unknown')}")
                lines.append(f"**Requires Auth:** {ep.get('classification', {}).get('requires_auth', False)}")
                lines.append(f"**Status:** {ep.get('status_code', 'Unknown')}\n")
                lines.append(f"**Why Important:** {ep.get('why_important', ep.get('classification', {}).get('reasoning', 'N/A'))}\n")
                
                recs = ep.get('classification', {}).get('recommendations', [])
                if recs:
                    lines.append("**Recommendations:**")
                    for rec in recs:
                        lines.append(f"- {rec}")
                lines.append("")
        else:
            lines.append("No critical or high-risk endpoints identified.")
        
        lines.append("\n## All Discovered Endpoints\n")
        lines.append("| Method | URL | Status | Type | Risk | Auth |")
        lines.append("|--------|-----|--------|------|------|------|")
        
        for ep in sorted(endpoints, key=lambda x: x.get('url', ''))[:100]:
            method = ep.get('method', 'GET')
            url = ep.get('url', '').replace('https://vulnbank.org', '').replace('http://vulnbank.org', '') or '/'
            status = ep.get('status_code', '-')
            ep_type = ep.get('classification', {}).get('type', 'UNKNOWN')[:12]
            risk = ep.get('classification', {}).get('risk_level', 'LOW')
            auth = "YES" if ep.get('classification', {}).get('requires_auth') else "NO"
            
            lines.append(f"| {method} | {url} | {status} | {ep_type} | {risk} | {auth} |")
        
        return "\n".join(lines)
    
    def _extract_critical(self, endpoints: List[Dict]) -> List[Dict]:
        """Extract critical and high-risk endpoints."""
        critical = []
        for ep in endpoints:
            risk = ep.get('classification', {}).get('risk_level', 'LOW')
            if risk in ['CRITICAL', 'HIGH']:
                critical.append(ep)
        return sorted(critical, key=lambda x: x.get('priority', 0), reverse=True)
    
    def print_console_summary(self, endpoints: List[Dict], summary: Dict) -> None:
        """Print summary to console."""
        print("\n" + "="*80)
        print("[*] DISCOVERY COMPLETE")
        print("="*80)
        
        print(f"\n[+] Summary:")
        print(f"    Target: {summary['target']}")
        print(f"    Duration: {summary['duration_seconds']:.1f}s")
        print(f"    Total Endpoints: {summary['total_endpoints']}")
        print(f"    Total Requests: {summary['total_requests']}")
        print(f"    Success Rate: {(summary['successful_requests'] / max(1, summary['total_requests']) * 100):.1f}%")
        
        print(f"\n[!] Risk Distribution:")
        for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = summary['endpoints_by_risk'].get(risk, 0)
            if count > 0:
                bars = "#" * min(count, 50)
                print(f"    {risk:10} {bars} ({count})")
        
        print(f"\n[*] Endpoint Types:")
        for ep_type, count in sorted(summary['endpoints_by_type'].items()):
            print(f"    {ep_type:15} {count}")
        
        print(f"\n[*] Top Priority Endpoints (for testing):\n")
        critical = self._extract_critical(endpoints)
        for i, ep in enumerate(critical[:10], 1):
            url = ep['url'].replace('https://vulnbank.org', '').replace('http://vulnbank.org', '') or '/'
            risk = ep.get('classification', {}).get('risk_level', 'LOW')
            purpose = ep.get('classification', {}).get('purpose', 'Unknown')[:50]
            print(f"    {i}. [{risk:8}] {ep.get('method', 'GET'):6} {url}")
            print(f"       => {purpose}")
            if ep.get('why_important'):
                print(f"       => Why: {ep.get('why_important')[:60]}")
            print()
        
        print("="*80)
