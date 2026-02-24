import os
from dotenv import load_dotenv

load_dotenv()

# Target configuration
TARGET = "https://vulnbank.org"
MAX_CONCURRENT_REQUESTS = 5
REQUEST_TIMEOUT = 10
RETRY_ATTEMPTS = 3
RATE_LIMIT_DELAY = 0.5  # seconds between requests

# LLM Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
LLM_MODEL = "gemini-1.5-flash"

# Discovery patterns
COMMON_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2",
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/.well-known", "/.well-known/openapi",
    "/graphql", "/graphql/schema",
    "/admin", "/admin/", "/admin/login",
    "/docs", "/documentation", "/api/docs",
    "/.env", "/config", "/config.json",
    "/backup", "/uploads", "/files",
    "/user", "/users", "/account", "/accounts",
    "/login", "/logout", "/register", "/auth",
    "/health", "/health-check", "/status",
    "/robots.txt", "/sitemap.xml",
]

# Classification patterns
API_PATTERNS = {
    "REST_API": {
        "patterns": ["/api/", "/v1/", "/v2/", "/v3/"],
        "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
    },
    "GRAPHQL": {
        "patterns": ["/graphql", "graphql"],
        "content_types": ["application/json"],
    },
    "GRPC": {
        "patterns": [".proto", "grpc"],
        "content_types": ["application/grpc"],
    },
    "FORM": {
        "methods": ["POST", "GET"],
        "content_types": ["application/x-www-form-urlencoded", "multipart/form-data"],
    },
}

# Output configuration
OUTPUT_DIR = "output"
REPORT_FORMAT = "json"  # json, html, markdown
