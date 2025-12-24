"""
VScanX Configuration Module
Contains all constants and configuration parameters
"""

# Version
VERSION = "2.1.0"

# Rate Limiting
DEFAULT_DELAY = 1.0  # seconds between requests
MAX_RETRIES = 3
TIMEOUT = 10  # seconds

# Network Scanning
DEFAULT_PORT_RANGE = (1, 1024)  # Common ports only
PORT_SCAN_TIMEOUT = 0.2  # seconds per port (optimized)
MAX_THREADS = 10  # For multi-threaded scanning

# XSS Detection
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
]

# SQL Injection Payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin'--",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
]

# Directory Enumeration
COMMON_DIRECTORIES = [
    # Admin & Authentication
    "admin",
    "administrator",
    "admin-panel",
    "backend",
    "login",
    "signin",
    "auth",
    "authenticate",
    "dashboard",
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    # API Endpoints
    "api",
    "api-v1",
    "api-v2",
    "v1",
    "v2",
    "v3",
    "rest",
    "graphql",
    "rpc",
    # Configuration & Secrets
    "config",
    "configuration",
    "settings",
    "env",
    ".env",
    "backup",
    "backups",
    "database",
    "db",
    ".git",
    ".svn",
    ".hg",
    # Development & Testing
    "test",
    "tests",
    "dev",
    "development",
    "staging",
    "debug",
    "debug-panel",
    "admin-debug",
    "wp-admin",
    # Web Content
    "uploads",
    "upload",
    "files",
    "downloads",
    "download",
    "images",
    "img",
    "pictures",
    "media",
    "assets",
    "static",
    "public",
    "css",
    "js",
    "javascript",
    "styles",
    "fonts",
    "vendor",
    # CMS & Frameworks
    "wp-content",
    "wp-includes",
    "plugins",
    "themes",
    "modules",
    "extensions",
    "addons",
    "packages",
    # Application Paths
    "application",
    "app",
    "src",
    "source",
    "code",
    "lib",
    "libs",
    "library",
    "include",
    "includes",
    "classes",
    "functions",
    "helpers",
    "utils",
    # Documentation & Info
    "documentation",
    "docs",
    "help",
    "about",
    "readme",
    "changelog",
    "license",
    # Miscellaneous
    "tmp",
    "temp",
    "temporary",
    "cache",
    "log",
    "logs",
    "data",
    "old",
    "new",
    "archive",
    "archives",
    "history",
    "private",
    "secret",
    "secure",
    "hidden",
]

COMMON_FILES = [
    # Configuration Files
    "robots.txt",
    "sitemap.xml",
    ".htaccess",
    "web.config",
    "config.php",
    "config.json",
    "config.xml",
    "config.ini",
    "settings.py",
    "settings.json",
    "wp-config.php",
    ".env",
    ".env.example",
    ".env.local",
    "database.yml",
    "database.xml",
    # Database & Data
    "database.sql",
    "backup.sql",
    "backup.zip",
    "backup.tar",
    "dump.sql",
    "export.sql",
    # Application Files
    "index.html",
    "index.php",
    "index.jsp",
    "index.aspx",
    "default.html",
    "default.php",
    "main.php",
    "app.py",
    "app.js",
    "server.js",
    "main.js",
    # Documentation
    "README.md",
    "readme.txt",
    "README.html",
    "CHANGELOG.md",
    "LICENCE",
    "LICENSE",
    "LICENSE.txt",
    "INSTALL.md",
    "install.txt",
    # Git & Version Control
    ".gitignore",
    ".gitmodules",
    ".gitconfig",
    ".git/config",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "Gemfile",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    # Security
    ".htpasswd",
    ".htpasswds",
    "ssh_keys",
    "private.key",
    "id_rsa",
    "rsa_key",
    # Build & Compilation
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "build.xml",
    "gradle.properties",
    "maven.xml",
    "pom.xml",
    # Logs
    "error.log",
    "access.log",
    "debug.log",
    "application.log",
    # Miscellaneous
    "web.xml",
    ".DS_Store",
    "thumbs.db",
    ".well-known",
    "crossdomain.xml",
]

# HTTP Security Headers to Check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# User Agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

# Report Settings
REPORT_TITLE = "VScanX Security Scan Report"
REPORT_OUTPUT_DIR = "reports"

# Scan Profiles
SCAN_PROFILES = {
    "quick": {
        "description": "Fast scan with minimal checks",
        "port_range": (80, 443),
        "max_threads": 5,
        "xss_payloads": 2,
        "sqli_payloads": 2,
        "check_directories": False,
        "check_headers": True,
        "delay": 0.5,
    },
    "normal": {
        "description": "Balanced scan with standard checks",
        "port_range": (1, 1024),
        "max_threads": 10,
        "xss_payloads": 3,
        "sqli_payloads": 3,
        "check_directories": True,
        "check_headers": True,
        "delay": 1.0,
    },
    "full": {
        "description": "Comprehensive scan with all checks",
        "port_range": (1, 65535),
        "max_threads": 20,
        "xss_payloads": 5,
        "sqli_payloads": 6,
        "check_directories": True,
        "check_headers": True,
        "delay": 1.5,
    },
    "stealth": {
        "description": "Slow, careful scan to avoid detection",
        "port_range": (1, 1024),
        "max_threads": 2,
        "xss_payloads": 2,
        "sqli_payloads": 2,
        "check_directories": False,
        "check_headers": True,
        "delay": 3.0,
    },
}

# Output Formats
EXPORT_FORMATS = ["html", "json", "csv", "txt"]
