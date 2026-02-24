#!/usr/bin/env python3
"""
API Discovery and Reconnaissance Tool
Finds and classifies API endpoints on target domains for security testing
"""

import asyncio
import sys
import os
import argparse
from pathlib import Path

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import config
from api_hunter import APIHunter
from llm_classifier import LLMClassifier
from report_generator import ReportGenerator


async def main():
    parser = argparse.ArgumentParser(
        description="Discover and classify APIs on a target domain"
    )
    parser.add_argument(
        '--target',
        default=config.TARGET,
        help=f"Target URL (default: {config.TARGET})"
    )
    parser.add_argument(
        '--output',
        default=config.OUTPUT_DIR,
        help=f"Output directory (default: {config.OUTPUT_DIR})"
    )
    parser.add_argument(
        '--format',
        choices=['json', 'markdown', 'both'],
        default='both',
        help="Output format"
    )
    parser.add_argument(
        '--no-llm',
        action='store_true',
        help="Disable LLM classification"
    )
    
    args = parser.parse_args()
    

    # Initialize classifier
    classifier = LLMClassifier() if not args.no_llm else None
    if args.no_llm:
        print("⚠️  LLM classification disabled. Using heuristic-based approach.\n")
    
    # Initialize hunter
    hunter = APIHunter(args.target, classifier)
    
    # Run discovery
    print(f"[*] Starting discovery...\n")
    endpoints = await hunter.discover()
    
    # Generate reports
    summary = hunter.get_summary()
    reporter = ReportGenerator(args.output)
    
    # Save reports
    if args.format in ['json', 'both']:
        json_report = reporter.save_json_report(endpoints, summary)
        print(f"[+] JSON report: {json_report}")
    
    if args.format in ['markdown', 'both']:
        md_report = reporter.save_markdown_report(endpoints, summary)
        print(f"[+] Markdown report: {md_report}")
    
    # Print console summary
    reporter.print_console_summary(endpoints, summary)
    
    print(f"\n[*] Done! All reports saved to: {args.output}/")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n[X] Discovery interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[X] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
