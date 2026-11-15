#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import html as html_lib
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sqlite3
import string
import subprocess
import sys
import time
import urllib.parse
from collections import deque, Counter
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import httpx
except ImportError:
    sys.stderr.write("httpx required: python3 -m pip install httpx\n")
    raise SystemExit(1)

try:
    import dns.asyncresolver
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import questionary
    HAS_QUESTIONARY = True
except ImportError:
    HAS_QUESTIONARY = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

VERSION = "6.0"

RESET = "\033[0m"
DIM = "\033[38;5;245m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
BOLD = "\033[1m"

console = Console() if HAS_RICH else None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm_host(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    return value.split("/")[0].split(":")[0].rstrip(".")


def norm_url(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    p = urllib.parse.urlsplit(value)
    path = p.path or "/"
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))


def short_body(body: str, limit: int = 600) -> str:
    return re.sub(r"\s+", " ", body or "").strip()[:limit]


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()


def simhash(text: str, bits: int = 64) -> int:
    if not text:
        return 0
    tokens = re.findall(r"\w+", text.lower())
    if not tokens:
        return 0
    v = [0] * bits
    for token in tokens:
        h = int(hashlib.md5(token.encode()).hexdigest(), 16)
        for i in range(bits):
            v[i] += 1 if (h & (1 << i)) else -1
    result = 0
    for i in range(bits):
        if v[i] > 0:
            result |= 1 << i
    return result


def hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def severity_rank(sev: str) -> int:
    return {"CRIT": 5, "HIGH": 4, "MED": 3, "LOW": 2, "INFO": 1}.get(sev, 0)


def random_token(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


@dataclass
class Evidence:
    request: str = ""
    status: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)
    snippet: str = ""
    elapsed: float = 0.0
    timestamp: str = field(default_factory=now_iso)


@dataclass
class Finding:
    title: str
    severity: str
    confidence: int
    category: str
    asset: str
    location: str = ""
    description: str = ""
    remediation: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            raw = "|".join([self.asset, self.location, self.category, self.title])
            self.fingerprint = sha256_text(raw)[:20]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Observation:
    asset: str
    kind: str
    data: dict[str, Any]
    timestamp: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Scope:
    def __init__(self, roots, allow_subdomains=True, excluded=None, ports=None,
                 allowed_schemes=("http", "https"), excluded_paths=None, cidrs=None):
        self.roots = {norm_host(x) for x in roots if x.strip()}
        self.allow_subdomains = allow_subdomains
        self.excluded = {norm_host(x) for x in (excluded or [])}
        self.excluded_paths = [re.compile(p) for p in (excluded_paths or [])]
        self.allowed_schemes = set(allowed_schemes)
        self.ports = set(ports or [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000])
        self.cidrs = []
        for c in (cidrs or []):
            try:
                self.cidrs.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                pass

    def host_allowed(self, host):
        host = norm_host(host)
        if not host or host in self.excluded:
            return False
        try:
            ip = ipaddress.ip_address(host)
            if self.cidrs:
                return any(ip in net for net in self.cidrs)
        except ValueError:
            pass
        for root in self.roots:
            if host == root:
                return True
            if self.allow_subdomains and host.endswith("." + root):
                return True
        return False

    def url_allowed(self, url):
        try:
            p = urllib.parse.urlsplit(url)
            if p.scheme not in self.allowed_schemes:
                return False
            if not self.host_allowed(p.hostname or ""):
                return False
            if p.port and p.port not in self.ports:
                return False
            for pat in self.excluded_paths:
                if pat.match(p.path or "/"):
                    return False
            return True
        except Exception:
            return False


class Store:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, kind TEXT, value TEXT UNIQUE, source TEXT, discovered TEXT);
        CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE, data TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY, asset TEXT, kind TEXT, data TEXT, created TEXT);
        """)
        self.conn.commit()

    def asset(self, kind, value, source=""):
        self.conn.execute("INSERT OR IGNORE INTO assets(kind,value,source,discovered) VALUES(?,?,?,?)",
                          (kind, value, source, now_iso()))
        self.conn.commit()

    def observation(self, asset, kind, data):
        self.conn.execute("INSERT INTO observations(asset,kind,data,created) VALUES(?,?,?,?)",
                          (asset, kind, json.dumps(data, ensure_ascii=False, default=str), now_iso()))
        self.conn.commit()

    def finding(self, f):
        cur = self.conn.execute("SELECT 1 FROM findings WHERE fingerprint=?", (f.fingerprint,))
        if cur.fetchone():
            return False
        self.conn.execute("INSERT INTO findings(fingerprint,data,created) VALUES(?,?,?)",
                          (f.fingerprint, json.dumps(f.to_dict(), ensure_ascii=False, default=str), now_iso()))
        self.conn.commit()
        return True


class RateLimiter:
    def __init__(self, rps):
        self.interval = 1.0 / rps if rps and rps > 0 else 0
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def wait(self):
        if not self.interval:
            return
        async with self.lock:
            delta = time.monotonic() - self.last
            if delta < self.interval:
                await asyncio.sleep(self.interval - delta)
            self.last = time.monotonic()


class HTTPClient:
    def __init__(self, scope, concurrency=20, rps=5.0, timeout=10.0, max_body=500_000,
                 verify_tls=True, retries=2, backoff_base=0.5, backoff_max=8.0):
        self.scope = scope
        self.sem = asyncio.Semaphore(concurrency)
        self.rate = RateLimiter(rps)
        self.timeout = timeout
        self.max_body = max_body
        self.retries = retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.http_cache = {}
        self.client = httpx.AsyncClient(
            follow_redirects=False, verify=verify_tls, http2=True,
            timeout=httpx.Timeout(connect=min(5.0, timeout), read=timeout, write=timeout, pool=timeout),
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency, keepalive_expiry=30),
            headers={"User-Agent": f"fox/{VERSION} detection-and-recon", "Accept": "*/*",
                     "Accept-Encoding": "gzip, deflate, br"},
        )

    async def request(self, method, url, **kwargs):
        if not self.scope.url_allowed(url):
            return {"ok": False, "status": None, "headers": {}, "body": "", "url": url,
                    "elapsed": 0.0, "error": "scope_violation"}
        await self.rate.wait()
        if method == "GET" and not kwargs.get("headers") and url in self.http_cache:
            etag, _, _ = self.http_cache[url]
            kwargs.setdefault("headers", {})["If-None-Match"] = etag
        async with self.sem:
            for attempt in range(self.retries + 1):
                start = time.monotonic()
                try:
                    r = await self.client.request(method, url, **kwargs)
                    body = r.content[:self.max_body].decode("utf-8", "ignore")
                    elapsed = time.monotonic() - start
                    if 300 <= r.status_code < 400:
                        loc = r.headers.get("location", "")
                        if loc:
                            target = urllib.parse.urljoin(url, loc)
                            if not self.scope.url_allowed(target):
                                return {"ok": True, "status": r.status_code, "headers": dict(r.headers),
                                        "body": body, "url": str(r.url), "elapsed": elapsed,
                                        "http_version": r.http_version, "attempts": attempt + 1,
                                        "redirect_out_of_scope": target}
                    if method == "GET" and r.status_code == 200:
                        etag = r.headers.get("etag")
                        if etag:
                            self.http_cache[url] = (etag, dict(r.headers), body)
                    if r.status_code in {429, 502, 503, 504} and attempt < self.retries:
                        retry_after = r.headers.get("retry-after", "")
                        wait = self.backoff_base * (2 ** attempt)
                        if retry_after.isdigit():
                            wait = min(float(retry_after), self.backoff_max)
                        wait *= 0.7 + (hash(url) % 100) / 200.0
                        await asyncio.sleep(wait)
                        continue
                    return {"ok": True, "status": r.status_code, "headers": dict(r.headers),
                            "body": body, "url": str(r.url), "elapsed": elapsed,
                            "http_version": r.http_version, "attempts": attempt + 1}
                except httpx.TimeoutException:
                    if attempt < self.retries:
                        await asyncio.sleep(self.backoff_base * (2 ** attempt))
                        continue
                    return {"ok": False, "status": None, "headers": {}, "body": "", "url": url,
                            "elapsed": time.monotonic() - start, "error": "timeout", "attempts": attempt + 1}
                except Exception as exc:
                    if attempt < self.retries:
                        await asyncio.sleep(self.backoff_base * (2 ** attempt))
                        continue
                    return {"ok": False, "status": None, "headers": {}, "body": "", "url": url,
                            "elapsed": time.monotonic() - start, "error": str(exc), "attempts": attempt + 1}

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def close(self):
        await self.client.aclose()


class Engine:
    def __init__(self, store):
        self.store = store
        self.findings = {}
        self.observations = []
        self.merged_evidence = {}

    def add(self, finding):
        existing = self.findings.get(finding.fingerprint)
        if existing:
            self.merged_evidence.setdefault(finding.fingerprint, []).append(finding.evidence)
            existing.confidence = min(existing.confidence + 5, 100)
            return False
        if self.store.finding(finding):
            self.findings[finding.fingerprint] = finding
            self.merged_evidence[finding.fingerprint] = [finding.evidence]
            return True
        return False

    def observe(self, asset, kind, data):
        self.observations.append(Observation(asset, kind, data))
        self.store.observation(asset, kind, data)

    def counts(self):
        out = {}
        for f in self.findings.values():
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def risk_score(finding, asset_criticality=3):
    base = {"CRIT": 9.5, "HIGH": 7.5, "MED": 5.0, "LOW": 2.5, "INFO": 1.0}
    b = base.get(finding.severity, 1.0)
    c = finding.confidence / 100.0
    a = min(asset_criticality / 4.0, 1.0)
    exposure = 1.0 if finding.category in {"exposed-service", "endpoint", "exposure"} else 0.8
    return round(b * c * a * exposure, 1)


DEFAULT_CONFIG = {
    "canaries": {"xss_html": "FOXBB_XSS_7F3A91", "ssti": "FOXBB_SSTI_91B2E7",
                 "redirect": "https://example.invalid/foxbb-redirect-7f3a"},
    "timeouts": {"http": 10.0, "dns": 3.0, "tcp": 1.5},
    "limits": {"max_pages": 50, "max_params": 10, "max_endpoints": 100, "max_active_probes": 100},
    "severity_overrides": {}, "excluded_paths": [],
    "soft404_hamming_threshold": 3, "soft404_length_tolerance": 0.05,
}


def load_config(path=None):
    config = DEFAULT_CONFIG.copy()
    if not path:
        path = os.environ.get("FOX_CONFIG", "fox.yaml")
    p = Path(path)
    if p.exists() and HAS_YAML:
        try:
            user = yaml.safe_load(p.read_text())
            if isinstance(user, dict):
                for k, v in user.items():
                    if isinstance(v, dict) and k in config:
                        config[k].update(v)
                    else:
                        config[k] = v
        except Exception:
            pass
    return config


CONFIG = load_config()
BB_CANARIES = CONFIG["canaries"]

SQL_SYNTAX_PROBES = ["'", '"', "')", '")']

INTERESTING_PARAMS = {
    "url", "uri", "link", "href", "src", "dest", "destination", "redirect", "redirect_uri",
    "return", "return_url", "next", "continue", "callback", "webhook", "feed", "image",
    "avatar", "file", "filename", "path", "page", "template", "view", "include", "lang",
    "locale", "q", "query", "search", "keyword", "name", "message", "comment", "content",
    "body", "title", "id", "uid", "user_id", "account_id", "tenant_id", "org_id", "project_id",
    "role", "admin", "debug", "format", "sort", "order", "filter", "fields", "expand",
    "select", "limit", "offset", "page_size", "token", "state", "code", "scope",
}

SENSITIVE_RESPONSE_MARKERS = {
    "stack_trace": ["traceback (most recent call last)", "stack trace", "exception in thread",
                    "at java.", "org.springframework", "django.core.exceptions", "werkzeug.exceptions"],
    "debug": ["debug toolbar", "debug=true", "development mode", "laravel ignition",
              "whoops, looks like something went wrong"],
    "credentials": ["authorization:", "bearer ", "access_token", "refresh_token",
                    "client_secret", "private_key"],
    "internal": ["127.0.0.1", "localhost", "10.", "172.16.", "192.168.",
                 "internal.", ".internal"],
}

COMMON_EXPOSURES = [
    ("/.git/HEAD", "Git metadata"), ("/.env", "Environment file"),
    ("/.env.local", "Local environment file"), ("/.env.production", "Production environment file"),
    ("/composer.json", "Composer manifest"), ("/package.json", "Node package manifest"),
    ("/package-lock.json", "Node lockfile"), ("/yarn.lock", "Yarn lockfile"),
    ("/Dockerfile", "Docker build file"), ("/docker-compose.yml", "Docker Compose file"),
    ("/.dockerignore", "Docker ignore file"), ("/phpinfo.php", "PHP information page"),
    ("/server-status", "Apache server-status"), ("/server-info", "Apache server-info"),
    ("/.well-known/assetlinks.json", "Android asset links"),
    ("/.well-known/apple-app-site-association", "Apple app association"),
]

SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
    "/v3/api-docs", "/graphql", "/health", "/healthz", "/ready", "/live",
    "/status", "/metrics", "/debug", "/actuator", "/actuator/health",
    "/.well-known/change-password", "/.well-known/host-meta", "/.well-known/nodeinfo",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/humans.txt", "/manifest.json",
    "/browserconfig.xml", "/apple-touch-icon.png", "/favicon.ico",
]

ENDPOINT_EXPECTATIONS = {
    "/openapi.json": {"ct": ("json",), "body_check": "openapi"},
    "/swagger.json": {"ct": ("json",), "body_check": "swagger"},
    "/swagger/v1/swagger.json": {"ct": ("json",), "body_check": "swagger"},
    "/v3/api-docs": {"ct": ("json",), "body_check": "openapi"},
    "/api-docs": {"ct": ("json", "yaml", "text"), "body_check": "openapi"},
    "/actuator": {"ct": ("json", "text"), "body_check": "json_object"},
    "/actuator/health": {"ct": ("json", "text"), "body_check": "json_object"},
    "/metrics": {"ct": ("text", "plain"), "body_check": "prometheus"},
    "/graphql": {"ct": ("json", "text"), "body_check": "graphql"},
}

HEADER_TESTS = {
    "strict-transport-security": "HSTS", "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options", "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy",
}

TECH_CONFIDENCE = {
    "Next.js": {"markers": ["__next_data__", "/_next/static/"], "weights": [70, 30], "min_context": ["structural", "structural"]},
    "Nuxt": {"markers": ["__nuxt__", "/_nuxt/"], "weights": [70, 30], "min_context": ["structural", "structural"]},
    "WordPress": {"markers": ["wp-content", "wp-includes", "wordpress"], "weights": [40, 30, 30], "min_context": ["structural", "structural", "body"]},
    "Drupal": {"markers": ["drupalsettings", "/sites/default/"], "weights": [60, 40], "min_context": ["structural", "structural"]},
    "Laravel": {"markers": ["laravel_session", "x-powered-by: php"], "weights": [50, 50], "min_context": ["structural", "structural"], "min_confidence": 50},
    "Django": {"markers": ["csrfmiddlewaretoken", "django"], "weights": [60, 40], "min_context": ["structural", "body"], "min_confidence": 50},
    "Spring": {"markers": ["jsessionid", "x-application-context"], "weights": [40, 60], "min_context": ["structural", "structural"]},
    "React": {"markers": ["react-dom", "_reactroot", "data-reactroot"], "weights": [50, 30, 20], "min_context": ["structural", "structural", "structural"]},
    "Vue": {"markers": ["__vue__", "data-v-"], "weights": [50, 50], "min_context": ["structural", "structural"]},
    "Angular": {"markers": ["ng-version", "ng-app"], "weights": [50, 50], "min_context": ["structural", "structural"]},
    "Joomla": {"markers": ["joomla", "/media/system/js/"], "weights": [50, 50], "min_context": ["body", "structural"]},
    "ASP.NET": {"markers": ["asp.net", "__viewstate", ".aspx"], "weights": [40, 40, 20], "min_context": ["structural", "structural", "structural"]},
    "Express": {"markers": ["x-powered-by: express"], "weights": [100], "min_context": ["structural"]},
    "PHP": {"markers": ["x-powered-by: php", "phpsessid"], "weights": [50, 50], "min_context": ["structural", "structural"]},
    "Cloudflare": {"markers": ["cf-ray", "cloudflare"], "weights": [60, 40], "min_context": ["structural", "structural"]},
    "Vercel": {"markers": ["x-vercel-id", "vercel"], "weights": [60, 40], "min_context": ["structural", "structural"]},
    "Netlify": {"markers": ["netlify", "x-nf-request-id"], "weights": [60, 40], "min_context": ["structural", "structural"]},
    "Akamai": {"markers": ["akamai", "x-akamai-transformed"], "weights": [50, 50], "min_context": ["structural", "structural"]},
    "Fastly": {"markers": ["fastly", "x-served-by"], "weights": [50, 50], "min_context": ["structural", "structural"]},
}

TECH_CPE_MAP = {
    "WordPress": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    "Drupal": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    "Joomla": "cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*",
    "Laravel": "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
    "Django": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    "Next.js": "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
    "React": "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*",
    "Angular": "cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*",
    "Spring": "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
    "nginx": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    "Apache": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "IIS": "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
    "PHP": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
}

WAF_MARKERS = {
    "Cloudflare": ["cf-ray", "cloudflare"], "Akamai": ["akamai", "akamai-"],
    "Fastly": ["fastly", "x-served-by"], "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
    "Vercel": ["x-vercel-id", "vercel"], "Netlify": ["netlify"],
    "Imperva": ["imperva", "incap_ses"], "F5": ["bigipserver", "f5"],
    "Sucuri": ["sucuri", "x-sucuri-id"], "ModSecurity": ["mod_security"],
}

PORT_SERVICES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
                 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
                 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
                 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}

SERVICE_SIGNATURES = {
    "ssh": ["SSH-2.0-", "SSH-1.99-"], "ftp": ["220 ", "FTP"], "smtp": ["220 ", "ESMTP"],
    "pop3": ["+OK"], "imap": ["* OK"], "mysql": ["mysql_native_password"],
    "redis": ["-ERR", "+PONG"], "elasticsearch": ['"cluster_name"', '"version"'],
    "mongodb": ["ismaster", "MongoDB"],
}

CLOUD_CNAME_MARKERS = {
    "amazonaws.com": "AWS", "cloudfront.net": "AWS CloudFront", "elb.amazonaws.com": "AWS ELB",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure",
    "blob.core.windows.net": "Azure Blob", "googleapis.com": "Google",
    "googlehosted.com": "Google", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "netlify.app": "Netlify", "vercel.app": "Vercel", "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers", "github.io": "GitHub Pages",
    "gitlab.io": "GitLab Pages", "fastly.net": "Fastly", "akamai.net": "Akamai",
    "azureedge.net": "Azure CDN", "myshopify.com": "Shopify",
}

DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]

SECRET_PATTERNS = {
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "Private key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JWT-like": r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    "Generic API key": r"(?i)\b(?:api[_-]?key|apikey)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    "Generic password": r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "Database URL": r"(?i)\b(?:postgres|mysql|mongodb|redis)://[^\s'\"<>]+",
}

TAINT_SOURCES = ["request.args", "request.form", "request.GET", "request.POST",
                 "request.body", "request.query_params", "sys.stdin",
                 "flask.request.args", "flask.request.form",
                 "django.request.GET", "django.request.POST"]

TAINT_SINKS = [("eval(", "code execution"), ("exec(", "code execution"),
               ("os.system(", "command execution"), ("subprocess.", "command execution"),
               ("pickle.loads(", "unsafe deserialization"), ("yaml.load(", "unsafe YAML deserialization"),
               ("render_template_string(", "template injection"), ("cursor.execute(", "sql injection")]

CVE_CACHE_PATH = Path.home() / ".fox" / "cve.db"

URL_RE = re.compile(r"""(?:"|')((?:https?:)?//[^"'\\\s]+|/[A-Za-z0-9_./?=&%:#\-]{2,})["']""", re.I)
JS_ENDPOINT_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|url|endpoint|route)\s*\(?\s*["'`]([^"'`]+)""", re.I)

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "HEAD"]

ERROR_SIGNATURES = {
    "Apache": ["apache", "the requested url was not found on this server"],
    "nginx": ["nginx", "404 not found"],
    "IIS": ["microsoft-iis", "iis"],
    "LiteSpeed": ["litespeed"],
    "lighttpd": ["lighttpd"],
    "Cloudflare": ["cloudflare", "cf-ray"],
}

COOKIE_FRAMEWORK_MAP = {
    "phpsessid": "PHP", "jsessionid": "Java/Tomcat", "asp.net_sessionid": "ASP.NET",
    "rack.session": "Ruby/Rack", "connect.sid": "Node.js/Express",
    "laravel_session": "Laravel", "csrfmiddlewaretoken": "Django",
    "_next": "Next.js", "__nuxt": "Nuxt", "s:": "Express signed cookie",
    "j:": "Express JSON cookie",
}

# Firme per rilevare se il server risponde in modo identico a qualsiasi path (SPA fallback)
SPA_FALLBACK_INDICATORS = ["<!doctype html", "<html", "<head", "<div id=\"root\"", "<div id=\"app\""]


async def resolve_full(host):
    out = {t: [] for t in DNS_RECORD_TYPES}
    if not HAS_DNS:
        try:
            out["A"] = sorted({x[4][0] for x in socket.getaddrinfo(host, 443)})
        except Exception:
            pass
        return out
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = CONFIG["timeouts"]["dns"]
    resolver.timeout = CONFIG["timeouts"]["dns"]

    async def one(typ):
        try:
            answers = await resolver.resolve(host, typ)
            return typ, [str(x).rstrip(".").strip('"') for x in answers]
        except Exception:
            return typ, []

    for typ, values in await asyncio.gather(*(one(t) for t in DNS_RECORD_TYPES)):
        out[typ] = values
    return out


def classify_cloud_cname(cname):
    cname = cname.lower().rstrip(".")
    for marker, provider in CLOUD_CNAME_MARKERS.items():
        if marker in cname:
            return provider
    return None


def _extract_structural_html(body):
    parts = []
    for m in re.finditer(r"<(?:script|link|meta)[^>]+>", body, re.I):
        parts.append(m.group(0).lower())
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", body, re.I | re.S):
        parts.append(m.group(1)[:5000].lower())
    return "\n".join(parts)


def detect_technologies_scored(headers, body, cookies=""):
    structural = _extract_structural_html(body)
    body_lower = body[:200_000].lower()
    header_hay = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    cookie_hay = cookies.lower()
    results = []
    for tech, config in TECH_CONFIDENCE.items():
        markers = config["markers"]
        weights = config["weights"]
        min_ctx = config.get("min_context", ["body"] * len(markers))
        min_conf = config.get("min_confidence", 20)
        confidence = 0
        evidence = []
        for marker, weight, ctx in zip(markers, weights, min_ctx):
            marker_l = marker.lower()
            present_structural = marker_l in structural or marker_l in header_hay or marker_l in cookie_hay
            present_body = marker_l in body_lower
            if ctx == "structural":
                if present_structural:
                    confidence += weight
                    evidence.append(f"{marker} [structural]")
                elif present_body:
                    confidence += weight // 4
                    evidence.append(f"{marker} [body-text]")
            else:
                if present_body:
                    confidence += weight
                    evidence.append(f"{marker} [body]")
        if confidence >= min_conf:
            results.append({"name": tech, "confidence": min(confidence, 100),
                            "evidence": evidence, "cpe": TECH_CPE_MAP.get(tech)})
    return sorted(results, key=lambda x: -x["confidence"])


def detect_waf(headers, body):
    hay = (" ".join(f"{k}:{v}" for k, v in headers.items()) + "\n" + body[:20_000]).lower()
    return sorted(name for name, markers in WAF_MARKERS.items()
                  if any(marker.lower() in hay for marker in markers))


def detect_server_from_error(body):
    low = body.lower()
    for server, markers in ERROR_SIGNATURES.items():
        if any(m.lower() in low for m in markers):
            return server
    return None


def detect_framework_from_cookies(headers):
    raw = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    found = []
    for cookie in raw:
        name = cookie.split("=", 1)[0].strip().lower()
        for pattern, framework in COOKIE_FRAMEWORK_MAP.items():
            if pattern in name:
                found.append(framework)
    return list(set(found))


def cookie_flags(headers):
    raw = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    out = []
    for cookie in raw:
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite=" not in low:
            missing.append("SameSite")
        if missing:
            out.append((name, ", ".join(missing)))
    return out


def cors_issue(origin, headers):
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        return {"severity": "HIGH", "confidence": 85,
                "description": "Wildcard ACAO with ACAC=true; non-browser tooling can leverage the combination."}
    if acao == origin and acac == "true":
        return {"severity": "HIGH", "confidence": 95,
                "description": f"Origin '{origin}' reflected in ACAO with ACAC=true; any origin can read authenticated responses."}
    if acao == origin and acac != "true":
        return {"severity": "LOW", "confidence": 40,
                "description": f"Origin '{origin}' reflected in ACAO without ACAC=true; low risk, verify sensitive endpoints."}
    return None


def init_cve_cache():
    CVE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CVE_CACHE_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cve_lookup (
            cpe TEXT NOT NULL, version TEXT, cve_id TEXT NOT NULL,
            cvss REAL, severity TEXT, description TEXT, published TEXT, fetched TEXT,
            PRIMARY KEY (cpe, version, cve_id)
        );
    """)
    conn.commit()
    return conn


async def update_cve_cache(cpes, api_key=None):
    conn = init_cve_cache()
    headers = {"apiKey": api_key} if api_key else {}
    sleep_secs = 1.0 if api_key else 6.0
    async with httpx.AsyncClient(headers=headers, timeout=60) as client:
        for cpe in cpes:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"virtualMatchString": cpe, "resultsPerPage": 2000}
            try:
                r = await client.get(url, params=params)
                if r.status_code != 200:
                    print(f"{YELLOW}[!]{RESET} NVD {cpe}: HTTP {r.status_code}")
                    await asyncio.sleep(sleep_secs)
                    continue
                data = r.json()
                n = 0
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                    cvss = 0.0
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        for metric in cve.get("metrics", {}).get(key, []):
                            cvss = float(metric.get("cvssData", {}).get("baseScore", 0.0))
                            break
                        if cvss:
                            break
                    severity = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MED" if cvss >= 4 else "LOW"
                    conn.execute("INSERT OR REPLACE INTO cve_lookup (cpe, version, cve_id, cvss, severity, description, published, fetched) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                 (cpe, None, cve_id, cvss, severity, desc[:500], cve.get("published", ""), now_iso()))
                    n += 1
                conn.commit()
                print(f"{GREEN}[+]{RESET} {cpe}: {n} CVEs cached")
            except Exception as e:
                print(f"{RED}[!]{RESET} {cpe}: {e}")
            await asyncio.sleep(sleep_secs)


def cve_lookup(cpe, version):
    if not CVE_CACHE_PATH.exists():
        return []
    conn = sqlite3.connect(str(CVE_CACHE_PATH))
    conn.row_factory = sqlite3.Row
    try:
        if version:
            cur = conn.execute("SELECT * FROM cve_lookup WHERE cpe=? AND (version=? OR version IS NULL) ORDER BY cvss DESC", (cpe, version))
        else:
            cur = conn.execute("SELECT * FROM cve_lookup WHERE cpe=? ORDER BY cvss DESC", (cpe,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def correlate_cve(tech, asset, engine):
    cpe = tech.get("cpe")
    if not cpe:
        return
    version = tech.get("versions", [None])[0] if tech.get("versions") else None
    for cve in cve_lookup(cpe, version):
        if cve["cvss"] and cve["cvss"] >= 7.0:
            engine.add(Finding(
                title=f"{cve['cve_id']} in {tech['name']}",
                severity="HIGH" if cve["cvss"] >= 9.0 else "MED",
                confidence=min(tech["confidence"], 85), category="cve", asset=asset, location=cpe,
                description=f"{cve['cve_id']} (CVSS {cve['cvss']}): {cve['description'][:200]}",
                remediation="Update the affected component to a patched version.",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}"],
            ))


def extract_links(base, body):
    out = set()
    for m in URL_RE.findall(body):
        u = "https:" + m if m.startswith("//") else urllib.parse.urljoin(base, m)
        if u.startswith(("http://", "https://")):
            out.add(u.split("#", 1)[0])
    return out


def extract_js_endpoints(base, body):
    out = set()
    for m in JS_ENDPOINT_RE.findall(body):
        if m.startswith(("http://", "https://", "/")):
            out.add(urllib.parse.urljoin(base, m))
    return out


async def crawl(start, scope, client, store, max_pages=50):
    q = deque([norm_url(start)])
    seen = set()
    links = set()
    endpoints = set()
    while q and len(seen) < max_pages:
        url = q.popleft()
        if url in seen or not scope.url_allowed(url):
            continue
        seen.add(url)
        r = await client.get(url)
        if not r["ok"] or r.get("redirect_out_of_scope"):
            continue
        store.observation(url, "http", {"status": r["status"], "headers": r["headers"], "elapsed": r["elapsed"]})
        for u in extract_links(url, r["body"]):
            if scope.url_allowed(u):
                links.add(u)
                if u not in seen and len(seen) + len(q) < max_pages:
                    q.append(u)
        for u in extract_js_endpoints(url, r["body"]):
            if scope.url_allowed(u):
                endpoints.add(u)
        for script in re.findall(r"""<script[^>]+src=["']([^"']+)""", r["body"], re.I):
            js = urllib.parse.urljoin(url, script)
            if scope.url_allowed(js):
                jr = await client.get(js)
                if jr["ok"]:
                    for ep in extract_js_endpoints(js, jr["body"]):
                        if scope.url_allowed(ep):
                            endpoints.add(ep)
    return links, endpoints


def parse_openapi(text):
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        if HAS_YAML:
            try:
                obj = yaml.safe_load(text)
                return obj if isinstance(obj, dict) else {}
            except Exception:
                pass
    return {}


def inspect_openapi(doc):
    findings = []
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        return findings
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                continue
            operation = operation if isinstance(operation, dict) else {}
            security = operation.get("security", doc.get("security"))
            if not security:
                findings.append({"type": "documented-no-security", "method": method.upper(), "path": path})
            text = json.dumps(operation, ensure_ascii=False).lower()
            if any(x in text for x in ["password", "token", "secret", "api_key"]):
                findings.append({"type": "sensitive-field-in-schema", "method": method.upper(), "path": path})
    return findings


def parse_query_params(url):
    try:
        return sorted({k for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True)})
    except Exception:
        return []


def replace_query_param(url, param, value):
    p = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    changed = False
    out = []
    for k, v in pairs:
        if k == param and not changed:
            out.append((k, value))
            changed = True
        else:
            out.append((k, v))
    if not changed:
        return url
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(out), ""))


async def safe_xss_probe(url, param, client):
    parsed = urllib.parse.urlsplit(url)
    qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    if param not in qs:
        return None
    canary = "FOX_XSS_9A7C"
    qs[param] = canary
    probe = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(qs), ""))
    r = await client.get(probe)
    if not r["ok"] or canary not in r["body"]:
        return None
    ct = r["headers"].get("content-type", "").lower()
    if "html" not in ct:
        return None
    return Finding(title="Reflected input", severity="LOW", confidence=45, category="reflection",
                   asset=url, location=param,
                   description="Inert canary reflected in HTML response; context-sensitive validation required.",
                   remediation="Apply context-aware output encoding and validate input handling.",
                   evidence=Evidence(request=probe, status=r["status"],
                                     headers={k: v for k, v in r["headers"].items() if k.lower() in {"content-type", "content-security-policy"}},
                                     snippet=short_body(r["body"].replace(canary, "[FOX_CANARY]")), elapsed=r["elapsed"]))


async def safe_sql_probe(url, param, client):
    parsed = urllib.parse.urlsplit(url)
    qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    if param not in qs:
        return None
    baseline = await client.get(url)
    if not baseline["ok"]:
        return None
    base_len = len(baseline["body"])
    base_status = baseline["status"]
    base_ct = baseline["headers"].get("content-type", "")
    for probe in SQL_SYNTAX_PROBES:
        qs[param] = probe
        u = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(qs), ""))
        r = await client.get(u)
        if not r["ok"]:
            continue
        body = r["body"]
        error_markers = ["sql syntax", "mysql", "postgresql", "pg_query", "ora-", "sqlite error", "microsoft sql server", "odbc"]
        if any(m in body.lower() for m in error_markers):
            return Finding(title="Potential SQL error disclosure", severity="MED", confidence=75,
                           category="sql-error", asset=url, location=param,
                           description="A syntax probe triggered a database-related error signature; detection only.",
                           remediation="Use parameterized queries and avoid exposing database errors to clients.",
                           evidence=Evidence(request=u, status=r["status"], snippet=short_body(body), elapsed=r["elapsed"]))
        status_changed = r["status"] != base_status
        ct_changed = r["headers"].get("content-type", "") != base_ct
        len_changed = abs(len(body) - base_len) > max(500, int(base_len * 0.8))
        if status_changed and ct_changed and len_changed:
            return Finding(title="Parameter response anomaly", severity="LOW", confidence=25,
                           category="input-anomaly", asset=url, location=param,
                           description="Multiple signals diverge from baseline; manual review recommended.",
                           remediation="Inspect server-side parameter parsing behavior.",
                           evidence=Evidence(request=u, status=r["status"], snippet=short_body(body), elapsed=r["elapsed"]))
    return None


def make_bb_finding(title, severity, confidence, category, asset, description, remediation,
                    request="", response=None, location=""):
    response = response or {}
    return Finding(title=title, severity=severity, confidence=confidence, category=category,
                   asset=asset, location=location, description=description, remediation=remediation,
                   evidence=Evidence(request=request, status=response.get("status"),
                                     headers={k: v for k, v in response.get("headers", {}).items()
                                              if k.lower() in {"content-type", "location", "server", "content-security-policy",
                                                               "access-control-allow-origin", "access-control-allow-credentials"}},
                                     snippet=short_body(response.get("body", "")), elapsed=response.get("elapsed", 0.0)))


def classify_reflection_context(body, canary):
    idx = body.find(canary)
    if idx < 0:
        return {"context": "not_found", "confidence": 0, "note": ""}
    before = body[max(0, idx - 50):idx]
    after = body[idx + len(canary):idx + len(canary) + 50]
    window = (before + after).lower()
    if "<script" in window and ">" not in before[-10:]:
        return {"context": "script_tag", "confidence": 85, "note": "Canary appears inside a script block"}
    if re.search(r'<[a-z][^>]*=\s*["\'][^"\']*$', before, re.I):
        return {"context": "attribute_quoted", "confidence": 65, "note": "Canary appears inside a quoted attribute value"}
    if re.search(r'<[a-z][^>]*=\s*[^"\'\s>]*$', before, re.I):
        return {"context": "attribute_unquoted", "confidence": 75, "note": "Canary appears inside an unquoted attribute value"}
    if re.search(r'<[^>]+$', before):
        return {"context": "html_tag", "confidence": 40, "note": "Canary appears inside an HTML tag"}
    if "javascript:" in window or "onerror=" in window or "onload=" in window:
        return {"context": "js_uri", "confidence": 70, "note": "Canary appears near a JS URI or event handler"}
    return {"context": "html_body", "confidence": 30, "note": "Canary reflected in HTML body context"}


async def bb_probe_reflection(url, param, client, engine):
    canary = BB_CANARIES["xss_html"]
    probe = replace_query_param(url, param, canary)
    r = await client.get(probe)
    if not r["ok"] or canary not in r.get("body", ""):
        return
    ct = r["headers"].get("content-type", "").lower()
    if "html" not in ct:
        return
    ctx = classify_reflection_context(r["body"], canary)
    sev = {"script_tag": "HIGH", "attribute_unquoted": "MED", "attribute_quoted": "LOW",
           "js_uri": "MED", "html_tag": "LOW", "html_body": "LOW"}.get(ctx["context"], "LOW")
    engine.add(make_bb_finding(f"Reflected canary ({ctx['context']})", sev, ctx["confidence"], "reflection", url,
                               f"{ctx['note']}. Inert canary; manual context validation required.",
                               "Apply context-aware output encoding for the specific insertion point.",
                               probe, r, param))


async def bb_probe_open_redirect(url, param, client, engine):
    marker = BB_CANARIES["redirect"]
    probe = replace_query_param(url, param, marker)
    r = await client.get(probe)
    if not r["ok"]:
        return
    loc = r.get("headers", {}).get("location", "")
    if loc and "example.invalid/foxbb-redirect-7f3a" in loc:
        engine.add(make_bb_finding("Potential open redirect", "MED", 90, "open-redirect", url,
                                   "A URL-like parameter influenced the Location header.",
                                   "Allow redirects only to explicit trusted destinations or use server-side identifiers.",
                                   probe, r, param))


async def bb_probe_ssti(url, param, client, engine):
    probes = ["{{FOXBB_SSTI_91B2E7}}", "${FOXBB_SSTI_91B2E7}", "<%=FOXBB_SSTI_91B2E7%>"]
    for payload in probes:
        probe = replace_query_param(url, param, payload)
        r = await client.get(probe)
        if not r["ok"]:
            continue
        body = r.get("body", "")
        if payload not in body and "FOXBB_SSTI_91B2E7" in body:
            engine.add(make_bb_finding("Potential template expression processing", "MED", 55, "ssti", url,
                                       "A non-executable template canary appears transformed by the server.",
                                       "Treat user-controlled template syntax as data; use strict templating boundaries.",
                                       probe, r, param))
            return


async def bb_probe_error_disclosure(url, param, client, engine):
    for payload in ["'", '"', "\\", "%00"]:
        probe = replace_query_param(url, param, payload)
        r = await client.get(probe)
        if not r["ok"]:
            continue
        body = r.get("body", "").lower()
        for group, markers in SENSITIVE_RESPONSE_MARKERS.items():
            hit = next((m for m in markers if m.lower() in body), None)
            if hit:
                sev = "MED" if group in {"stack_trace", "debug"} else "LOW"
                engine.add(make_bb_finding(f"Potential {group.replace('_', ' ')} disclosure", sev, 80, "error-disclosure", url,
                                           f"A malformed-input probe exposed a response marker: {hit}",
                                           "Return generic client errors and keep diagnostic details server-side.",
                                           probe, r, param))
                return


async def bb_probe_parameter(url, param, client, engine):
    await bb_probe_reflection(url, param, client, engine)
    await bb_probe_open_redirect(url, param, client, engine)
    await bb_probe_ssti(url, param, client, engine)
    await bb_probe_error_disclosure(url, param, client, engine)


def discover_parameters_from_html(base, body):
    params = set()
    for m in re.finditer(r"""<(?:input|textarea|select)[^>]+(?:name|id)=["']([^"']+)""", body, re.I):
        params.add(m.group(1))
    for form in re.findall(r"<form[^>]*>(.*?)</form>", body, re.I | re.S):
        for m in re.finditer(r"""name=["']([^"']+)""", form, re.I):
            params.add(m.group(1))
    return params


def bb_parameter_priority(params):
    def score(p):
        low = p.lower()
        if low in INTERESTING_PARAMS:
            return 100
        if any(x in low for x in INTERESTING_PARAMS):
            return 70
        if re.search(r"(id|url|path|token|key|query|search|redirect)", low):
            return 50
        return 10
    return sorted(params, key=lambda p: (-score(p), p.lower()))


async def bb_exposure_sweep(base, scope, client, engine):
    for path, label in COMMON_EXPOSURES:
        u = urllib.parse.urljoin(base, path)
        if not scope.url_allowed(u):
            continue
        r = await client.get(u)
        if not r["ok"] or r["status"] not in {200, 206}:
            continue
        body = r.get("body", "")
        ct = r["headers"].get("content-type", "").lower()
        suspicious = False
        if path == "/.git/HEAD":
            suspicious = body.startswith("ref: refs/")
        elif path.startswith("/.env"):
            suspicious = bool(re.search(r"(?m)^(?:APP_KEY|DB_|AWS_|SECRET|PASSWORD|TOKEN)[A-Z0-9_]*\s*=", body))
        elif path == "/package.json":
            suspicious = body.lstrip().startswith("{") and '"dependencies"' in body
        elif path in {"/composer.json", "/package-lock.json", "/yarn.lock"}:
            suspicious = len(body) > 20 and ("html" not in ct)
        elif path in {"/phpinfo.php", "/server-status", "/server-info"}:
            suspicious = len(body) > 100 and ("html" in ct)
        else:
            suspicious = len(body) > 20 and ("html" not in ct)
        if suspicious:
            severity = "HIGH" if path.startswith("/.env") or path == "/.git/HEAD" else "MED"
            engine.add(make_bb_finding(f"Potentially exposed {label}", severity, 95, "exposure", base,
                                       f"{path} returned HTTP {r['status']} with content consistent with {label}.",
                                       "Remove the exposed resource or restrict it to authorized administrative access.",
                                       u, r, path))


async def bb_bug_bounty_web(args, scope, client, store, engine):
    base = norm_url(args.target)
    if not scope.url_allowed(base):
        raise ValueError("Target outside scope")
    r = await client.get(base)
    if not r["ok"]:
        return
    await bb_exposure_sweep(base, scope, client, engine)
    for p in ["/.well-known/security.txt", "/security.txt"]:
        u = urllib.parse.urljoin(base, p)
        rr = await client.get(u)
        if rr["ok"] and rr["status"] == 200:
            store.observation(base, "security.txt", analyze_security_txt(rr["body"]))
            break
    links, endpoints = await crawl(base, scope, client, store, max_pages=min(args.max_pages, 100))
    discovered = set(endpoints) | {base} | links
    pages = list(discovered)[:args.max_endpoints]
    all_param_targets = []
    for u in pages:
        rr = await client.get(u)
        if not rr["ok"]:
            continue
        params = set(parse_query_params(u))
        params |= discover_parameters_from_html(u, rr["body"])
        for p in bb_parameter_priority(params)[:args.max_params]:
            all_param_targets.append((u, p))
    seen = set()
    active = []
    for u, p in all_param_targets:
        key = (u, p)
        if key not in seen:
            seen.add(key)
            active.append(key)
    active = active[:args.max_active_probes]
    print(f"{CYAN}[*]{RESET} discovery targets: {len(discovered)}")
    print(f"{CYAN}[*]{RESET} prioritized parameters: {len(active)}")
    if args.active:
        for u, p in active:
            await bb_probe_parameter(u, p, client, engine)
    for u in sorted(discovered):
        if urllib.parse.urlsplit(u).path.lower().endswith("/graphql"):
            rr = await client.get(u)
            if rr["ok"]:
                ct = rr["headers"].get("content-type", "")
                store.observation(u, "graphql", {"status": rr["status"], "content_type": ct})
                if rr["status"] in {200, 400, 405} and "json" in ct:
                    engine.add(make_bb_finding("GraphQL endpoint discovered", "INFO", 95, "graphql", u,
                                               "A GraphQL-like endpoint was discovered during crawling.",
                                               "Review authentication, authorization, introspection policy, depth/complexity limits.",
                                               u, rr))


def analyze_security_txt(body):
    fields = {}
    for line in body.splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            k, v = line.split(":", 1)
            fields.setdefault(k.strip().lower(), []).append(v.strip())
    return {"contacts": fields.get("contact", []), "policy": fields.get("policy", []),
            "expires": fields.get("expires", []), "canonical": fields.get("canonical", [])}


def scan_secrets(path):
    out = []
    skip_ext = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".zip", ".gz", ".pdf"}
    for file in path.rglob("*"):
        if not file.is_file() or file.stat().st_size > 2_000_000:
            continue
        if file.suffix.lower() in skip_ext:
            continue
        try:
            text = file.read_text(errors="ignore")
        except Exception:
            continue
        for name, pattern in SECRET_PATTERNS.items():
            m = re.search(pattern, text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                out.append(Finding(title=f"Potential secret: {name}", severity="HIGH", confidence=70,
                                   category="secret", asset=str(file), location=f"line {line}",
                                   description="Potential credential matched a secret heuristic; value not printed.",
                                   remediation="Rotate exposed credentials, remove from source control, use a secret manager."))
    return out


def scan_python_taint(path):
    out = []
    for file in path.rglob("*.py"):
        if file.stat().st_size > 2_000_000:
            continue
        try:
            lines = file.read_text(errors="ignore").splitlines()
        except Exception:
            continue
        tainted = set()
        for idx, line in enumerate(lines, 1):
            if any(src in line for src in TAINT_SOURCES):
                for var in re.findall(r"\b([A-Za-z_]\w*)\b", line):
                    tainted.add(var)
            for sink, label in TAINT_SINKS:
                if sink in line and any(re.search(rf"\b{re.escape(v)}\b", line) for v in tainted):
                    out.append(Finding(title=f"Potential taint flow: {label}", severity="HIGH", confidence=60,
                                       category="taint", asset=str(file), location=f"line {idx}",
                                       description=f"Possible user-controlled data reaching {sink}; static heuristic.",
                                       remediation="Validate, constrain and encode untrusted data before security-sensitive sinks."))
    return out


async def tls_info(host, port=443):
    def work():
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                return {"tls_version": s.version(), "cipher": s.cipher()[0] if s.cipher() else None,
                        "subject": str(cert.get("subject")), "issuer": str(cert.get("issuer")),
                        "notAfter": cert.get("notAfter")}
    try:
        return await asyncio.to_thread(work)
    except Exception as exc:
        return {"error": str(exc)}


async def port_check(host, port, timeout=1.5):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def scan_ports(host, ports, concurrency=100):
    sem = asyncio.Semaphore(concurrency)

    async def one(p):
        async with sem:
            return p if await port_check(host, p) else None

    results = await asyncio.gather(*(one(p) for p in sorted(ports)))
    return [p for p in results if p is not None]


async def grab_banner(host, port, timeout=2.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        if port in (80, 8000, 8008, 8080, 8888):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = data.decode("utf-8", "ignore").strip()[:300]
        except asyncio.TimeoutError:
            banner = ""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return banner
    except Exception:
        return ""


def identify_service(banner, port):
    bl = banner.lower()
    for svc, markers in SERVICE_SIGNATURES.items():
        if any(m.lower() in bl for m in markers):
            return svc
    return PORT_SERVICES.get(port, "unknown")


def validate_endpoint_body(path, body, content_type):
    exp = ENDPOINT_EXPECTATIONS.get(path)
    if not exp:
        return True
    ct_ok = any(w in content_type for w in exp["ct"])
    if not ct_ok:
        return False
    check = exp.get("body_check")
    if not check:
        return True
    low = body.lower()
    if check == "openapi":
        try:
            doc = json.loads(body)
            return isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc or "paths" in doc)
        except Exception:
            return "openapi" in low or "swagger" in low
    if check == "swagger":
        try:
            doc = json.loads(body)
            return isinstance(doc, dict) and ("swagger" in doc or "openapi" in doc)
        except Exception:
            return "swagger" in low or "openapi" in low
    if check == "json_object":
        try:
            doc = json.loads(body)
            return isinstance(doc, dict) and len(doc) > 0
        except Exception:
            return False
    if check == "prometheus":
        return "#" in body and any(m in body for m in ["_total", "_count", "_bucket", "_sum"])
    if check == "graphql":
        return "graphql" in low or "query" in low or "mutation" in low
    return True


async def calibrate_soft404(target, client):
    token = random_token(16)
    probes = [f"/fox-cal-{token}", f"/fox-cal-{token}.html", f"/fox-cal-{token}/x/y"]
    samples = []
    for p in probes:
        u = urllib.parse.urljoin(target, p)
        r = await client.get(u)
        if r["ok"]:
            samples.append({"url": u, "status": r["status"], "len": len(r["body"]),
                            "hash": simhash(short_body(r["body"], 2000)),
                            "ct": r["headers"].get("content-type", "").lower(),
                            "body_head": short_body(r["body"], 200)})
    if len(samples) < 2:
        return None
    statuses = {s["status"] for s in samples}
    if len(statuses) == 1:
        status = samples[0]["status"]
        common_hash = samples[0]["hash"]
        lengths = [s["len"] for s in samples]
        avg_len = sum(lengths) / len(lengths)
        is_spa = any(marker in samples[0]["body_head"].lower() for marker in SPA_FALLBACK_INDICATORS)
        return {"status": status, "hash": common_hash, "avg_len": avg_len,
                "tolerance": max(50, int(avg_len * CONFIG["soft404_length_tolerance"])),
                "ct": samples[0]["ct"], "samples": len(samples), "spa_fallback": is_spa}
    return None


async def mode_web(args, scope, client, store, engine):
    target = norm_url(args.target)
    if not scope.url_allowed(target):
        raise ValueError("Target outside scope")
    print(f"{CYAN}[*]{RESET} HTTP fingerprint: {target}")
    r = await client.get(target)
    if not r["ok"]:
        print(f"{RED}[!]{RESET} {r.get('error')}")
        return

    headers = r["headers"]
    body = r["body"]

    # === OSSERVAZIONI PASSIVE ===
    store.asset("url", target, "target")
    engine.observe(target, "response", {
        "status": r["status"], "http_version": r.get("http_version"),
        "elapsed": r["elapsed"], "server": headers.get("server"),
        "content_type": headers.get("content-type"),
        "content_length": len(body),
    })

    print(f"{GREEN}[+]{RESET} {r['status']} {r['elapsed']:.2f}s (HTTP/{r.get('http_version','?')})")

    server = headers.get("server", "")
    if server:
        print(f"  server: {server}")
        engine.observe(target, "server_header", {"value": server})

    # Header fingerprinting estremo: ordine, presenza, valori
    header_order = list(headers.keys())
    engine.observe(target, "header_order", {"order": header_order[:30]})

    # Fingerprint header hash (rimuove valori, tiene solo nomi+ordine)
    header_names_only = "|".join(k.lower() for k in header_order)
    header_hash = sha256_text(header_names_only)[:16]
    print(f"  header_fingerprint: {header_hash}")
    engine.observe(target, "header_fingerprint", {"hash": header_hash, "names": header_names_only})

    # Error page signature
    if r["status"] != 200:
        err_sig = detect_server_from_error(body)
        if err_sig:
            print(f"  error_signature: {err_sig}")
            engine.observe(target, "error_signature", {"server": err_sig, "status": r["status"]})
        # Estrai anche la prima riga del body per capire il formato di errore
        first_line = body.strip().split("\n")[0][:120] if body.strip() else ""
        if first_line:
            engine.observe(target, "error_body_head", {"first_line": first_line})

    # Tecnologie
    cookies_str = " ".join(v for k, v in headers.items() if k.lower() == "set-cookie")
    techs = detect_technologies_scored(headers, body, cookies_str)
    if techs:
        print(f"  technologies:")
        for t in techs:
            print(f"    {t['name']:<20} {t['confidence']:>3}%  evidence={t['evidence']}")
            store.asset("technology", t["name"], "http-fingerprint")
            engine.observe(target, "technology", t)
            correlate_cve(t, target, engine)

    # Framework da cookie
    fw_cookies = detect_framework_from_cookies(headers)
    if fw_cookies:
        print(f"  framework (cookie): {', '.join(fw_cookies)}")
        engine.observe(target, "framework_from_cookie", {"frameworks": fw_cookies})

    # WAF
    wafs = detect_waf(headers, body)
    print(f"  waf/cdn: {', '.join(wafs) or 'none detected'}")
    if wafs:
        engine.observe(target, "waf", {"detected": wafs})

    # Cookie raw (per analisi)
    raw_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    if raw_cookies:
        engine.observe(target, "cookies", {"raw": [c[:200] for c in raw_cookies]})

    # Security headers
    low_headers = {k.lower(): v for k, v in headers.items()}
    for key, label in HEADER_TESTS.items():
        if key not in low_headers:
            sev = "MED" if key in {"strict-transport-security", "content-security-policy"} else "LOW"
            engine.add(Finding(title=f"Missing {label}", severity=sev, confidence=95,
                               category="security-header", asset=target,
                               description=f"{label} not present in the HTTP response.",
                               remediation=f"Configure {label} according to the application's security requirements."))

    # Cookie flags
    for name, missing in cookie_flags(headers):
        engine.add(Finding(title=f"Cookie flags missing: {name}", severity="MED", confidence=90,
                           category="cookie", asset=target, location=name,
                           description=f"Missing flags: {missing}",
                           remediation="Set Secure, HttpOnly and an appropriate SameSite policy."))

    # CORS
    cors = cors_issue(target, headers)
    if cors:
        engine.add(Finding(title="Potentially unsafe CORS policy", severity=cors["severity"],
                           confidence=cors["confidence"], category="cors", asset=target,
                           description=cors["description"],
                           remediation="Use an explicit trusted-origin allowlist and avoid credentialed wildcard CORS."))

    # === CALIBRAZIONE SOFT-404 PRIMA DEI METODI HTTP ===
    calibration = await calibrate_soft404(target, client)
    if calibration:
        print(f"{CYAN}[*]{RESET} soft-404 calibration: status={calibration['status']} "
              f"samples={calibration['samples']} avg_len={calibration['avg_len']:.0f} "
              f"spa_fallback={calibration.get('spa_fallback', False)}")
        engine.observe(target, "soft404_calibration", calibration)

    # === METODI HTTP (con anti-falsi-positivi) ===
    # Un metodo è "sospetto" solo se restituisce 200/201/202 E il body è diverso dalla baseline
    # Se il server è una SPA che risponde 404 a tutto, TUTTI i metodi restituiscono 404 → non è un finding
    print(f"  HTTP methods:")
    method_results = {}
    for method in HTTP_METHODS:
        mr = await client.request(method, target)
        if not mr["ok"]:
            method_results[method] = {"status": None, "error": mr.get("error")}
            print(f"    {method:<8} error")
            continue
        status = mr["status"]
        method_results[method] = {"status": status, "body_len": len(mr["body"])}
        print(f"    {method:<8} {status}")

        # Anti-falso-positivo: se il server risponde 404 a GET, allora un 404 su PUT/DELETE/PATCH
        # NON significa che il metodo sia abilitato. Significa solo che il path non esiste.
        # Solo se GET restituisce 200/201/202 E il metodo restituisce 200/201/202, allora è sospetto.
        if method in {"PUT", "DELETE", "PATCH", "TRACE"}:
            base_status = method_results.get("GET", {}).get("status")
            if base_status in {200, 201, 202} and status in {200, 201, 202}:
                # Confronta il body con quello di GET
                get_body_len = method_results.get("GET", {}).get("body_len", 0)
                body_similar = abs(len(mr["body"]) - get_body_len) < max(50, int(get_body_len * 0.1))
                if not body_similar:
                    engine.add(Finding(title=f"Potentially dangerous HTTP method: {method}",
                                       severity="MED", confidence=70, category="http-method",
                                       asset=target, location=method,
                                       description=f"GET returns {base_status} but {method} returns {status} with different body size; verify if state-changing is intended.",
                                       remediation="Disable unnecessary HTTP methods at the reverse proxy or application layer."))
                else:
                    # Body identico a GET → probabilmente è la stessa pagina, non un'azione separata
                    engine.observe(target, "http_method_ignored", {"method": method,
                                                                    "reason": "body_similar_to_GET"})
            elif status in {405, 501, 403}:
                # Metodo esplicitamente non permesso → OK
                pass
            elif status == 404:
                # 404 su PUT/DELETE/PATCH quando GET è 404 → il path non esiste, non è un finding
                pass

    if method_results:
        engine.observe(target, "http_methods", method_results)

    # Redirect chain
    redirect_chain = []
    current_url = target
    for _ in range(5):
        rr = await client.get(current_url)
        if not rr["ok"]:
            break
        if 300 <= rr["status"] < 400:
            loc = rr["headers"].get("location", "")
            if loc:
                redirect_chain.append({"from": current_url, "status": rr["status"], "to": loc})
                current_url = urllib.parse.urljoin(current_url, loc)
                continue
        break
    if redirect_chain:
        print(f"  redirect chain: {len(redirect_chain)} hop(s)")
        engine.observe(target, "redirect_chain", {"chain": redirect_chain})

    # Crawl
    if args.crawl:
        links, endpoints = await crawl(target, scope, client, store, args.max_pages)
        print(f"{GREEN}[+]{RESET} crawl: {len(links)} links, {len(endpoints)} JS/API endpoints")
        for ep in sorted(endpoints)[:100]:
            print(f"  {DIM}{ep}{RESET}")
        engine.observe(target, "crawl", {"links": len(links), "endpoints": len(endpoints),
                                          "endpoint_samples": sorted(endpoints)[:50]})

    baseline_hash = simhash(short_body(body, 2000))
    baseline_len = len(body)

    # Endpoint discovery con validazione
    for path in SENSITIVE_PATHS:
        u = urllib.parse.urljoin(target, path)
        if not scope.url_allowed(u):
            continue
        rr = await client.get(u)
        if not rr["ok"]:
            continue
        rbody = rr.get("body", "")
        rct = rr["headers"].get("content-type", "").lower()

        if rr["status"] in {401, 403}:
            engine.observe(target, "endpoint_protected", {"path": path, "status": rr["status"]})
            continue

        if rr["status"] == 204:
            continue

        if calibration and rr["status"] == calibration["status"]:
            if hamming_distance(calibration["hash"], simhash(short_body(rbody, 2000))) <= CONFIG["soft404_hamming_threshold"]:
                continue
            if calibration["ct"] and rct and calibration["ct"] == rct and abs(len(rbody) - calibration["avg_len"]) < calibration["tolerance"]:
                continue

        if hamming_distance(baseline_hash, simhash(short_body(rbody, 2000))) <= CONFIG["soft404_hamming_threshold"]:
            continue
        if baseline_len and abs(len(rbody) - baseline_len) < max(50, int(baseline_len * CONFIG["soft404_length_tolerance"])):
            continue

        if not validate_endpoint_body(path, rbody, rct):
            engine.observe(target, "endpoint_invalid", {"path": path, "status": rr["status"],
                                                        "content_type": rct,
                                                        "reason": "body_validation_failed"})
            continue

        engine.observe(target, "endpoint_valid", {"path": path, "status": rr["status"],
                                                   "content_type": rct, "body_len": len(rbody)})
        sev = "INFO"
        if path in {"/actuator", "/debug", "/metrics", "/env"} and rr["status"] == 200:
            sev = "MED"
        engine.add(Finding(title=f"Interesting endpoint: {path}", severity=sev, confidence=90,
                           category="endpoint", asset=target, location=path,
                           description=f"Endpoint returned HTTP {rr['status']} with validated content-type {rct}.",
                           evidence=Evidence(request=u, status=rr["status"], snippet=short_body(rbody), elapsed=rr["elapsed"])))

    # OpenAPI
    for path in ["/openapi.json", "/swagger.json", "/v3/api-docs"]:
        u = urllib.parse.urljoin(target, path)
        rr = await client.get(u)
        if rr["ok"] and rr["status"] == 200 and validate_endpoint_body(path, rr["body"], rr["headers"].get("content-type", "")):
            doc = parse_openapi(rr["body"])
            if doc:
                items = inspect_openapi(doc)
                print(f"{GREEN}[+]{RESET} OpenAPI {path}: {len(doc.get('paths', {}))} paths")
                engine.observe(target, "openapi", {"path": path, "paths": len(doc.get("paths", {})),
                                                    "items": len(items)})
                for item in items[:100]:
                    engine.add(Finding(title=f"OpenAPI review: {item['type']}", severity="INFO", confidence=30,
                                       category="openapi", asset=target, location=f"{item['method']} {item['path']}",
                                       description="OpenAPI metadata indicates a potentially sensitive or unauthenticated operation; verify manually.",
                                       remediation="Confirm the intended authorization model for this operation."))
                break

    # Parametri query attivi
    parsed = urllib.parse.urlsplit(target)
    params = [k for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
    if args.active and params:
        for p in params[:args.max_params]:
            f = await safe_xss_probe(target, p, client)
            if f:
                engine.add(f)
            f = await safe_sql_probe(target, p, client)
            if f:
                engine.add(f)


async def mode_subdomains(args, scope, client, store, engine):
    root = next(iter(scope.roots))
    print(f"{CYAN}[*]{RESET} passive discovery: {root}")
    results = set()
    results |= await crtsh_subdomains(root, client, scope, store)
    results |= await hackertarget_subdomains(root, client, scope, store)
    if args.brute:
        words = ["www", "api", "app", "dev", "test", "staging", "stage", "admin", "portal",
                 "mail", "vpn", "auth", "login", "cdn", "static", "assets", "docs", "status",
                 "monitor", "grafana", "git", "gitlab", "jenkins", "ci", "registry", "sso",
                 "shop", "store", "blog", "support", "help", "m", "mobile", "beta", "demo"]
        print(f"{CYAN}[*]{RESET} DNS brute: {len(words)} candidates")
        results |= await brute_subdomains(root, words, scope, store)
    print(f"{GREEN}[+]{RESET} {len(results)} subdomains")
    for host in sorted(results):
        full = await resolve_full(host)
        cname = full["CNAME"][0] if full["CNAME"] else ""
        cloud = classify_cloud_cname(cname) if cname else None
        extra = f" CNAME={cname[:40]} [{cloud}]" if cname else ""
        print(f"  {host:<42} A={','.join(full['A'][:3])}{extra}")
        store.asset("subdomain_full", host, "resolver")
        engine.observe(host, "dns", full)
        if cloud:
            engine.add(Finding(title=f"Cloud CNAME to {cloud}", severity="INFO", confidence=90,
                               category="cloud-cname", asset=host, location=cname,
                               description=f"CNAME points to {cloud} ({cname})",
                               remediation="Verify that the cloud resource is still owned by the organization."))


async def mode_ports(args, scope, client, store, engine):
    host = norm_host(args.target)
    if not scope.host_allowed(host):
        raise ValueError("Target outside scope")
    print(f"{CYAN}[*]{RESET} TCP inventory: {host}")
    ports = await scan_ports(host, scope.ports, args.port_concurrency)
    print(f"{GREEN}[+]{RESET} open ports: {', '.join(map(str, ports)) or 'none'}")
    for port in ports:
        banner = await grab_banner(host, port)
        service = identify_service(banner, port)
        store.asset("port", f"{host}:{port}", "tcp-connect")
        engine.observe(f"{host}:{port}", "service", {"port": port, "service": service, "banner": banner[:200]})
        sev = "INFO"
        if service in {"Telnet", "Redis", "Memcached", "MongoDB", "Elasticsearch", "VNC", "RDP"}:
            sev = "MED"
        engine.add(Finding(title=f"Exposed service: {service}", severity=sev, confidence=90,
                           category="exposed-service", asset=f"{host}:{port}",
                           description=f"TCP port {port} accepted a connection; service fingerprint is {service}.",
                           remediation="Restrict administrative/data-plane services to trusted networks.",
                           evidence=Evidence(request=f"tcp://{host}:{port}", snippet=banner[:200])))
        if banner:
            print(f"  {port:>5} {service:<14} {DIM}{banner[:60]}{RESET}")
        else:
            print(f"  {port:>5} {service:<14}")
    if 443 in ports:
        tls = await tls_info(host)
        engine.observe(host, "tls", tls)
        if "error" not in tls:
            print(f"  TLS: {tls.get('tls_version')} / {tls.get('cipher')}")


async def mode_static(args, scope, client, store, engine):
    path = Path(args.path).resolve()
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")
    print(f"{CYAN}[*]{RESET} secret scan")
    for f in scan_secrets(path):
        engine.add(f)
    print(f"{CYAN}[*]{RESET} Python taint heuristics")
    for f in scan_python_taint(path):
        engine.add(f)
    semgrep_path = shutil_which("semgrep")
    if args.semgrep and semgrep_path:
        print(f"{CYAN}[*]{RESET} Semgrep")
        try:
            p = subprocess.run(["semgrep", "--config", "p/security-audit", "--json", "--quiet", "--metrics=off", str(path)],
                               capture_output=True, text=True, timeout=600)
            data = json.loads(p.stdout or "{}")
            for item in data.get("results", []):
                raw_sev = str(item.get("extra", {}).get("severity", "WARNING")).upper()
                sev = {"ERROR": "HIGH", "WARNING": "MED", "INFO": "LOW"}.get(raw_sev, "LOW")
                engine.add(Finding(title=item.get("check_id", "Semgrep finding"), severity=sev, confidence=80,
                                   category="semgrep", asset=str(path),
                                   location=f"{item.get('path')}:{item.get('start', {}).get('line', '')}",
                                   description=item.get("extra", {}).get("message", "Semgrep finding")))
        except Exception as exc:
            print(f"{YELLOW}[!]{RESET} Semgrep failed: {exc}")


def shutil_which(name):
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(p) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def print_summary(engine):
    counts = engine.counts()
    total = len(engine.findings)
    obs_count = len(engine.observations)
    print("\n" + "=" * 70)
    print(f"{BOLD}fox {VERSION} — summary{RESET}")
    print("=" * 70)
    print(f"Findings: {total}")
    for sev in ["CRIT", "HIGH", "MED", "LOW", "INFO"]:
        print(f"  {sev:<5} {counts.get(sev, 0)}")
    print(f"Observations (profile data): {obs_count}")

    if engine.observations:
        kinds = Counter(o.kind for o in engine.observations)
        print(f"\nProfile breakdown:")
        for kind, count in kinds.most_common():
            print(f"  {kind:<26} {count}")

    ranked = sorted(engine.findings.values(), key=lambda f: -risk_score(f))[:10]
    if ranked:
        print(f"\nTop 10 by risk:")
        for f in ranked:
            print(f"  {risk_score(f):>4.1f}  {f.severity:<5}  {f.confidence:>3}%  {f.category:<18}  {f.title[:55]}")


def export_json(engine, path, target):
    payload = {
        "tool": "fox", "version": VERSION, "target": target, "generated": now_iso(),
        "summary": engine.counts(),
        "observations_count": len(engine.observations),
        "observations": [o.to_dict() for o in engine.observations],
        "findings": [f.to_dict() for f in engine.findings.values()],
    }
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def export_sarif(engine, path, target):
    rules = {}
    results = []
    for f in engine.findings.values():
        if f.category not in rules:
            rules[f.category] = {"id": f.category, "name": f.category.replace("-", " ").title(),
                                 "shortDescription": {"text": f.category},
                                 "help": {"text": f.remediation or "Review the finding and apply appropriate mitigation."},
                                 "properties": {"tags": ["security", "fox"]}}
        results.append({"ruleId": f.category, "ruleIndex": list(rules.keys()).index(f.category),
                        "level": "error" if severity_rank(f.severity) >= 4 else "warning",
                        "message": {"text": f.description or f.title},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.asset},
                                                          "region": {"snippet": {"text": f.location[:200]}}}}],
                        "fingerprints": {"fox/v1": f.fingerprint},
                        "properties": {"severity": f.severity, "confidence": f.confidence, "risk_score": risk_score(f)}})
    payload = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
               "runs": [{"tool": {"driver": {"name": "fox", "version": VERSION, "rules": list(rules.values())}},
                         "results": results, "invocations": [{"executionSuccessful": True, "endTimeUtc": now_iso()}]}]}
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def export_html(engine, path, target):
    counts = engine.counts()
    rows = []
    for f in sorted(engine.findings.values(), key=lambda x: (-severity_rank(x.severity), -risk_score(x), x.category)):
        rows.append(f"<tr class='{f.severity}'><td>{f.severity}</td><td>{f.confidence}%</td><td>{risk_score(f):.1f}</td>"
                    f"<td>{html_lib.escape(f.category)}</td><td>{html_lib.escape(f.title)}</td>"
                    f"<td>{html_lib.escape(f.asset)}</td><td>{html_lib.escape(f.location)}</td></tr>")

    obs_rows = []
    for o in engine.observations[:800]:
        obs_rows.append(f"<tr><td>{html_lib.escape(o.kind)}</td><td>{html_lib.escape(o.asset)}</td>"
                        f"<td><pre>{html_lib.escape(json.dumps(o.data, ensure_ascii=False)[:400])}</pre></td></tr>")

    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>fox — {html_lib.escape(target)}</title>
<style>body{{font-family:system-ui;background:#0b0d10;color:#e8e8e8;margin:0;padding:30px}}
h1{{margin:0 0 4px}}small{{color:#888}}.summary{{display:flex;gap:16px;margin:24px 0;flex-wrap:wrap}}
.badge{{padding:10px 16px;background:#15181c;border-radius:6px;border:1px solid #2a2d33;min-width:80px}}
.badge b{{display:block;font-size:22px;margin-bottom:4px}}.CRIT{{color:#ff6b6b}}.HIGH{{color:#ffb070}}
.MED{{color:#ffe070}}.LOW{{color:#88c4ff}}.INFO{{color:#888}}table{{width:100%;border-collapse:collapse;margin-top:24px}}
th,td{{border:1px solid #2a2d33;padding:9px;vertical-align:top;text-align:left;font-size:13px}}
th{{background:#171a1f;font-weight:600}}tr.CRIT td:first-child{{color:#ff6b6b;font-weight:bold}}
tr.HIGH td:first-child{{color:#ffb070;font-weight:bold}}tr.MED td:first-child{{color:#ffe070}}
pre{{margin:0;white-space:pre-wrap;word-break:break-all;font-size:11px}}</style></head>
<body><h1>fox {VERSION}</h1><small>Target: {html_lib.escape(target)} · Generated: {now_iso()}</small>
<div class="summary"><div class="badge"><b>{len(engine.findings)}</b>total findings</div>
<div class="badge"><b class="CRIT">{counts.get("CRIT",0)}</b>critical</div>
<div class="badge"><b class="HIGH">{counts.get("HIGH",0)}</b>high</div>
<div class="badge"><b class="MED">{counts.get("MED",0)}</b>medium</div>
<div class="badge"><b class="LOW">{counts.get("LOW",0)}</b>low</div>
<div class="badge"><b class="INFO">{counts.get("INFO",0)}</b>info</div>
<div class="badge"><b>{len(engine.observations)}</b>observations</div></div>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Confidence</th><th>Risk</th><th>Category</th><th>Title</th><th>Asset</th><th>Location</th></tr>
{''.join(rows)}</table>
<h2>Observations (profile data)</h2>
<table><tr><th>Kind</th><th>Asset</th><th>Data</th></tr>
{''.join(obs_rows)}</table>
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")


def interactive_mode():
    if not HAS_QUESTIONARY:
        print(f"{RED}questionary required for interactive mode.{RESET}")
        print("Install: python3 -m pip install questionary")
        sys.exit(1)
    if HAS_RICH and console:
        console.print(Panel.fit("[bold cyan]fox[/bold cyan] — interactive detection & recon", border_style="cyan"))
    else:
        print("=" * 50)
        print("fox — interactive detection & recon")
        print("=" * 50)
    target = questionary.text("Target (domain/host/URL):", default="").ask()
    if not target:
        print(f"{RED}Target required.{RESET}")
        sys.exit(1)
    mode = questionary.select("Mode:", choices=[
        "web — HTTP fingerprint, headers, endpoints",
        "subdomains — passive + optional DNS brute",
        "ports — TCP scan + banners + TLS",
        "static — local source analysis",
        "full — subdomains + ports + web",
    ]).ask()
    mode_key = mode.split(" — ")[0]
    advanced = questionary.confirm("Configure advanced options?", default=False).ask()
    kwargs = {"target": target, "mode": mode_key, "no_subdomains": False, "brute": False,
              "crawl": False, "active": False, "bb": False, "semgrep": False,
              "insecure": False, "path": ".", "db": "fox.db", "output": "fox_report",
              "concurrency": 20, "port_concurrency": 100, "rps": 5.0, "timeout": 10.0,
              "retries": 2, "max_body": 500_000, "max_pages": 50, "max_params": 10,
              "max_endpoints": 100, "max_active_probes": 100,
              "ports": "80,443,8000,8008,8080,8081,8443,8888,3000,5000",
              "exclude": [], "exclude_path": [], "cidr": [], "cve_api_key": None,
              "report": False}
    if advanced:
        if mode_key in {"web", "full"}:
            kwargs["crawl"] = questionary.confirm("Crawl links and JS endpoints?", default=True).ask()
            kwargs["bb"] = questionary.confirm("Enable bug-bounty modules (exposure sweep, GraphQL)?", default=False).ask()
            if kwargs["bb"]:
                kwargs["active"] = questionary.confirm("Enable active probes (reflection/SSTI/redirect/error)?", default=False).ask()
        if mode_key in {"subdomains", "full"}:
            kwargs["brute"] = questionary.confirm("DNS brute-force subdomains?", default=False).ask()
            kwargs["no_subdomains"] = questionary.confirm("Block subdomains outside root?", default=False).ask()
        if mode_key in {"static"}:
            kwargs["path"] = questionary.path("Source directory:", default=".").ask()
            kwargs["semgrep"] = questionary.confirm("Use Semgrep if installed?", default=False).ask()
        if mode_key in {"web", "full", "ports"}:
            kwargs["insecure"] = questionary.confirm("Disable TLS verification (internal test only)?", default=False).ask()
        if mode_key in {"web", "full"}:
            kwargs["rps"] = float(questionary.text("Requests per second:", default="5").ask() or 5)
            kwargs["concurrency"] = int(questionary.text("Concurrency:", default="20").ask() or 20)
    kwargs["report"] = questionary.confirm("Generate report files (JSON/SARIF/HTML)?", default=False).ask()
    return kwargs


def build_parser():
    p = argparse.ArgumentParser(prog="fox", description="fox — detection and recon tool with profile output")
    p.add_argument("mode", nargs="?", choices=["subdomains", "web", "ports", "static", "full", "update-cve"],
                   help="run mode (omit for interactive)")
    p.add_argument("target", nargs="?", default="", help="authorized domain/host/URL")
    p.add_argument("--path", default=".", help="directory for static mode")
    p.add_argument("--db", default="fox.db")
    p.add_argument("--output", default="fox_report")
    p.add_argument("--report", action="store_true", help="generate JSON/SARIF/HTML report files")
    p.add_argument("--concurrency", type=int, default=20)
    p.add_argument("--port-concurrency", type=int, default=100)
    p.add_argument("--rps", type=float, default=5.0)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--max-body", type=int, default=500_000)
    p.add_argument("--max-pages", type=int, default=50)
    p.add_argument("--max-params", type=int, default=10)
    p.add_argument("--max-endpoints", type=int, default=100)
    p.add_argument("--max-active-probes", type=int, default=100)
    p.add_argument("--ports", default="80,443,8000,8008,8080,8081,8443,8888,3000,5000")
    p.add_argument("--exclude", action="append", default=[])
    p.add_argument("--exclude-path", action="append", default=[])
    p.add_argument("--cidr", action="append", default=[])
    p.add_argument("--no-subdomains", action="store_true")
    p.add_argument("--brute", action="store_true")
    p.add_argument("--crawl", action="store_true")
    p.add_argument("--active", action="store_true", help="enable inert reflection/error probes")
    p.add_argument("--semgrep", action="store_true")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--bb", action="store_true", help="enable bug-bounty modules")
    p.add_argument("--cve-api-key", default=None, help="optional NVD API key for update-cve")
    p.add_argument("--config", default=None, help="path to fox.yaml configuration file")
    p.add_argument("--interactive", action="store_true", help="force interactive mode")
    return p


async def main_async(args):
    roots = [norm_host(args.target)]
    scope = Scope(roots=roots, allow_subdomains=not args.no_subdomains, excluded=args.exclude,
                  ports=[int(x) for x in args.ports.split(",") if x.strip()],
                  excluded_paths=args.exclude_path or [], cidrs=args.cidr or [])
    store = Store(args.db)
    engine = Engine(store)
    client = HTTPClient(scope=scope, concurrency=args.concurrency, rps=args.rps,
                        timeout=args.timeout, max_body=args.max_body,
                        verify_tls=not args.insecure, retries=args.retries)
    try:
        if args.mode == "subdomains":
            await mode_subdomains(args, scope, client, store, engine)
        elif args.mode == "web":
            await mode_web(args, scope, client, store, engine)
            if args.bb:
                await bb_bug_bounty_web(args, scope, client, store, engine)
        elif args.mode == "ports":
            await mode_ports(args, scope, client, store, engine)
        elif args.mode == "static":
            await mode_static(args, scope, client, store, engine)
        elif args.mode == "full":
            await mode_subdomains(args, scope, client, store, engine)
            await mode_ports(args, scope, client, store, engine)
            await mode_web(args, scope, client, store, engine)
            if args.bb:
                await bb_bug_bounty_web(args, scope, client, store, engine)
        else:
            raise ValueError("Unknown mode")
    finally:
        await client.close()

    print_summary(engine)

    if getattr(args, "report", False):
        base = Path(args.output)
        base.parent.mkdir(parents=True, exist_ok=True)
        export_json(engine, str(base.with_suffix(".json")), args.target)
        export_sarif(engine, str(base.with_suffix(".sarif")), args.target)
        export_html(engine, str(base.with_suffix(".html")), args.target)
        print(f"\nReports:")
        print(f"  JSON   {base.with_suffix('.json')}")
        print(f"  SARIF  {base.with_suffix('.sarif')}")
        print(f"  HTML   {base.with_suffix('.html')}")
        print(f"  SQLite {args.db}")
    else:
        print(f"\nNo report files generated (use --report to write JSON/SARIF/HTML).")
        print(f"SQLite session database: {args.db}")


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.config:
        global CONFIG
        CONFIG = load_config(args.config)
    if args.interactive or (not args.mode and not args.target):
        if not HAS_QUESTIONARY:
            print(f"{RED}Interactive mode requires questionary.{RESET}")
            print("Install: python3 -m pip install questionary")
            sys.exit(1)
        kwargs = interactive_mode()
        for k, v in kwargs.items():
            setattr(args, k, v)
        args.mode = kwargs.get("mode", "web")
        args.target = kwargs.get("target", "")
    if args.mode == "update-cve":
        cpes = [
            "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
        ]
        print(f"{CYAN}[*]{RESET} updating CVE cache from NVD")
        try:
            asyncio.run(update_cve_cache(cpes, api_key=args.cve_api_key))
        except KeyboardInterrupt:
            print("\nInterrupted.")
        return
    if args.mode != "static" and not args.target:
        parser.error("target is required for this mode")
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as exc:
        print(f"{RED}fox error:{RESET} {exc}")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
