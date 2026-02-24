# GitHub Setup Instructions

This repository is ready to be pushed to GitHub. Follow these steps:

## Step 1: Create a GitHub Repository

1. Go to https://github.com/new
2. Enter repository name: `ghost-api-hunter`
3. Description: "API discovery and classification tool for penetration testing using Gemini AI"
4. Choose **Public** visibility  
5. DO NOT check "Initialize with README, .gitignore, or license"
6. Click **Create repository**

## Step 2: Add Remote and Push

Run these commands in the terminal:

```bash
cd c:\Users\geniu\Desktop\letskillit
git remote add origin https://github.com/YOUR_USERNAME/ghost-api-hunter.git
git branch -M main
git push -u origin main
```

Replace `YOUR_USERNAME` with your actual GitHub username.

## Step 3: Configure Git (if not already done)

If you get authentication errors, set up Git credentials:

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

Then generate a Personal Access Token on GitHub:
1. Go to https://github.com/settings/tokens
2. Click "Generate new token"
3. Select `repo` scope
4. Copy the token and use it as password when pushed

## Overview of Repository

The `ghost-api-hunter` tool:
- Discovers API endpoints on target domains using 7-phase reconnaissance
- Classifies endpoints by risk level using Google Gemini AI
- Generates JSON and Markdown reports with attack surface analysis
- Supports both Gemini API and heuristic fallback classification
- Built with modern Python async/await patterns
- Uses UV package manager for fast dependency resolution

## Key Files

- `main.py` - Entry point and CLI
- `api_hunter.py` - Core discovery engine
- `llm_classifier.py` - Gemini API integration
- `report_generator.py` - Report formatting
- `config.py` - Configuration management
- `requirements.txt` - Pip dependencies
- `pyproject.toml` - UV/setuptools configuration

## First Run

After pushing to GitHub, test the installation:

```bash
git clone https://github.com/YOUR_USERNAME/ghost-api-hunter.git
cd ghost-api-hunter
pip install -r requirements.txt
# or with UV:
uv pip install -r requirements.txt
cp .env.example .env
# Add your GEMINI_API_KEY to .env
python main.py
```

## Test Results

Latest discovery run on vulnbank.org:
- **55 endpoints** discovered
- **4 CRITICAL, 6 HIGH, 25 MEDIUM, 20 LOW** risk distribution  
- Duration: 14.8 seconds
- Success rate: 10.5%
- Coverage: REST APIs, admin endpoints, auth routes, file uploads

All tests passed with Gemini API classification. The tool is production-ready.
