"""DevGuard Python Guard Core Module.

Provides zero-dependency anti-theft, domain authorization, milestone autolock,
fail-safe open policy, and SEO-safe HTTP 503 lockout generation.
Compatible with Python 3.7 through 3.13+.
"""

import html
import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Union
import urllib.error
import urllib.request


class DevGuardConfig:
    """Configuration container for DevGuard Python Guard."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        allowed_domains: Optional[Union[List[str], str]] = None,
        allowed_paths: Optional[List[str]] = None,
        fail_safe: Optional[bool] = None,
        cache_ttl: Optional[int] = None,
        trust_proxy: Optional[bool] = None,
        timeout: Optional[float] = None,
        fetch_status: Optional[Any] = None,
    ):
        self.project_id = str(project_id or os.getenv("DEVGUARD_PROJECT_ID", "")).strip()
        self.api_url = (api_url or os.getenv("DEVGUARD_API_URL", "https://api.devguard.uk")).rstrip("/")
        self.api_key = api_key or os.getenv("DEVGUARD_API_KEY", None)

        raw_domains = allowed_domains if allowed_domains is not None else os.getenv("DEVGUARD_ALLOWED_DOMAINS")
        if isinstance(raw_domains, str):
            self.allowed_domains = [d.strip() for d in raw_domains.split(",") if d.strip()]
        elif isinstance(raw_domains, (list, tuple)):
            self.allowed_domains = [str(d).strip() for d in raw_domains if str(d).strip()]
        else:
            self.allowed_domains = None

        self.allowed_paths = list(allowed_paths) if allowed_paths is not None else None

        # Fail-Safe default is True ('open')
        if fail_safe is not None:
            self.fail_safe = bool(fail_safe)
        else:
            env_fs = os.getenv("DEVGUARD_FAIL_SAFE", "open").strip().lower()
            self.fail_safe = env_fs not in ("closed", "false", "0")

        # Cache TTL default 300 seconds
        if cache_ttl is not None:
            self.cache_ttl = max(5, int(cache_ttl))
        else:
            try:
                self.cache_ttl = max(5, int(os.getenv("DEVGUARD_CACHE_TTL", "300")))
            except ValueError:
                self.cache_ttl = 300

        # Proxy trust default False
        if trust_proxy is not None:
            self.trust_proxy = bool(trust_proxy)
        else:
            self.trust_proxy = os.getenv("DEVGUARD_TRUST_PROXY", "false").strip().lower() in ("true", "1", "yes")

        # Timeout default 3.0s
        self.timeout = float(timeout) if timeout is not None else 3.0
        self.fetch_status = fetch_status


class DomainMatcher:
    """Host extraction, normalization, and allowlist matcher."""

    @staticmethod
    def normalize_host(host: Optional[str]) -> str:
        """Strips port, lowercases, and sanitizes header injection characters."""
        if not host:
            return ""

        h = str(host).strip().lower()

        # Reject header injection or invalid characters
        if any(c in h for c in ("\r", "\n", "\0", "/", "@", "?", "#")):
            return ""

        # Remove trailing FQDN dot
        if h.endswith("."):
            h = h[:-1]

        # Handle IPv6 [::1]:8080
        if h.startswith("["):
            bracket_end = h.find("]")
            if bracket_end != -1:
                return h[1:bracket_end]

        # Remove port :8080
        if ":" in h:
            h = h.split(":", 1)[0]

        return h

    @staticmethod
    def is_domain_allowed(host: str, allowed_domains: Optional[Union[List[str], str]]) -> bool:
        """Matches normalized host against allowed domain rules (supports *.example.com)."""
        if not allowed_domains:
            return True

        if isinstance(allowed_domains, str):
            domains = [d.strip() for d in allowed_domains.split(",") if d.strip()]
        else:
            domains = list(allowed_domains)

        if not domains:
            return True

        norm_host = DomainMatcher.normalize_host(host)
        if not norm_host:
            return False

        for rule in domains:
            norm_rule = DomainMatcher.normalize_host(rule)
            if not norm_rule:
                continue

            # Wildcard all
            if norm_rule == "*":
                return True

            # Wildcard subdomain (*.example.com)
            if norm_rule.startswith("*."):
                root = norm_rule[2:]
                # Matches exact apex (example.com) or direct/nested subdomain (foo.example.com)
                if norm_host == root or norm_host.endswith("." + root):
                    return True
            else:
                if norm_host == norm_rule:
                    return True

        return False


class LockResponse:
    """Path bypass rules and HTTP 503 lock response renderer."""

    DEFAULT_ALLOWED_PATHS = (
        "/health",
        "/api/health",
        "/healthz",
        "/livez",
        "/readyz",
        "/.well-known",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
    )

    @classmethod
    def is_path_allowed(cls, path: Optional[str], custom_allowed_paths: Optional[List[str]] = None) -> bool:
        """Checks if request path is exempt from lock enforcement."""
        if not path:
            return False

        norm_path = path if path.startswith("/") else "/" + path

        for allowed in cls.DEFAULT_ALLOWED_PATHS:
            if norm_path == allowed or norm_path.startswith(allowed + "/"):
                return True

        if custom_allowed_paths:
            for rule in custom_allowed_paths:
                r = str(rule).strip()
                if not r:
                    continue
                # Regex rule: #^/api/webhook#
                if len(r) > 2 and r[0] in ("/", "#", "~") and r[-1] == r[0]:
                    pattern = r[1:-1]
                    try:
                        if re.search(pattern, norm_path):
                            return True
                    except re.error:
                        pass
                else:
                    norm_r = r if r.startswith("/") else "/" + r
                    if norm_path == norm_r or norm_path.startswith(norm_r + "/"):
                        return True

        return False

    @classmethod
    def render_json(cls, details: Dict[str, Any]) -> Dict[str, Any]:
        """Builds lock JSON payload."""
        return {
            "status": "locked",
            "code": details.get("code", "DEVGUARD_PROJECT_LOCKED"),
            "title": details.get("title", "Service Temporarily Suspended"),
            "message": details.get("message", "This application is temporarily unavailable."),
            "appName": details.get("appName"),
            "contactEmail": details.get("contactEmail"),
            "contactPhone": details.get("contactPhone"),
            "contactWhatsapp": details.get("contactWhatsapp"),
            "reason": details.get("reason", "project_locked"),
        }

    @classmethod
    def render_html(cls, details: Dict[str, Any]) -> str:
        """Builds responsive, professional HTML 503 lock screen."""
        title = html.escape(str(details.get("title") or "Service Temporarily Suspended"))
        message = html.escape(str(details.get("message") or "This website or application is currently suspended."))
        app_name = html.escape(str(details.get("appName") or "Application"))
        email = details.get("contactEmail")
        phone = details.get("contactPhone")
        whatsapp = details.get("contactWhatsapp")

        contact_buttons = []
        if email:
            safe_email = html.escape(str(email))
            contact_buttons.append(
                f'<a href="mailto:{safe_email}" style="display:inline-block;padding:12px 24px;margin:6px;'
                f'background:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;">'
                f'Contact via Email</a>'
            )
        if phone:
            safe_phone = html.escape(str(phone))
            contact_buttons.append(
                f'<a href="tel:{safe_phone}" style="display:inline-block;padding:12px 24px;margin:6px;'
                f'background:#059669;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;">'
                f'Call Support</a>'
            )
        if whatsapp:
            safe_wa = html.escape(str(whatsapp))
            contact_buttons.append(
                f'<a href="https://wa.me/{safe_wa}" style="display:inline-block;padding:12px 24px;margin:6px;'
                f'background:#16a34a;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;">'
                f'WhatsApp Developer</a>'
            )

        buttons_html = "".join(contact_buttons) if contact_buttons else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }}
    .card {{
      max-width: 580px;
      width: 100%;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 40px;
      text-align: center;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }}
    .badge {{
      display: inline-block;
      padding: 4px 12px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.4);
      border-radius: 9999px;
      margin-bottom: 20px;
    }}
    h1 {{
      font-size: 26px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 14px;
      line-height: 1.3;
    }}
    p {{
      font-size: 15px;
      color: #94a3b8;
      line-height: 1.6;
      margin-bottom: 28px;
    }}
    .footer {{
      margin-top: 32px;
      padding-top: 20px;
      border-top: 1px solid #334155;
      font-size: 12px;
      color: #64748b;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Security Notice</div>
    <h1>{title}</h1>
    <p>{message}</p>
    <div class="actions">
      {buttons_html}
    </div>
    <div class="footer">
      Protected by <strong>DevGuard</strong> &bull; {app_name}
    </div>
  </div>
</body>
</html>"""


class DevGuard:
    """Core DevGuard inspection and verification engine for Python."""

    def __init__(self, config: Optional[DevGuardConfig] = None, **kwargs):
        if config is not None:
            self.config = config
        else:
            self.config = DevGuardConfig(**kwargs)

        self._cache: Dict[str, Any] = {}
        self._cache_lock = threading.Lock()

    def resolve_status(self) -> Dict[str, Any]:
        """Queries remote DevGuard API status or returns cached entry.

        Implements failSafe: 'open' policy on network failures.
        """
        cache_key = f"devguard_status_{self.config.project_id}"
        now = time.monotonic()

        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached and now < cached["expires_at"]:
                return cached["data"]

        # If custom fetch callable is provided
        if self.config.fetch_status and callable(self.config.fetch_status):
            try:
                data = self.config.fetch_status(self.config.project_id)
                if isinstance(data, dict):
                    with self._cache_lock:
                        self._cache[cache_key] = {"data": data, "expires_at": now + self.config.cache_ttl}
                    return data
            except Exception as e:
                return self._handle_fetch_error(cache_key, e)

        # If project_id is empty, bypass
        if not self.config.project_id:
            return {"status": "active"}

        # HTTP query to DevGuard status endpoint
        endpoint = f"{self.config.api_url}/api/v1/plugins/autolock/status"
        payload = json.dumps({"projectId": self.config.project_id}).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "DevGuard-Python-Guard/1.0.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
            headers["X-DevGuard-Key"] = self.config.api_key

        req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                status_code = resp.getcode()
                raw_body = resp.read().decode("utf-8")
                if 200 <= status_code < 300:
                    data = json.loads(raw_body)
                    with self._cache_lock:
                        self._cache[cache_key] = {"data": data, "expires_at": now + self.config.cache_ttl}
                    return data
        except Exception as e:
            return self._handle_fetch_error(cache_key, e)

        return {"status": "active"}

    def _handle_fetch_error(self, cache_key: str, error: Exception) -> Dict[str, Any]:
        """Handles network/parsing error according to fail-safe policy."""
        # 1. Fallback to stale cached entry if available
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached and isinstance(cached.get("data"), dict):
                return cached["data"]

        # 2. Fail-safe OPEN: grant access on failure
        if self.config.fail_safe:
            return {
                "status": "active",
                "failSafeFallback": True,
                "error": str(error),
            }

        # 3. Fail-safe CLOSED: block access
        return {
            "status": "locked",
            "code": "DEVGUARD_VERIFICATION_UNAVAILABLE",
            "title": "Security Verification Unavailable",
            "message": "Security verification service is temporarily unreachable. Please retry shortly.",
            "failSafeFallback": True,
            "error": str(error),
        }

    def check_request(self, host: Optional[str] = None, path: Optional[str] = "/") -> Dict[str, Any]:
        """Checks whether the incoming request is authorized to proceed.

        Returns a dictionary with 'allowed' (bool) and diagnostic metadata.
        """
        # 1. Check Path Allowlist
        norm_path = path or "/"
        if LockResponse.is_path_allowed(norm_path, self.config.allowed_paths):
            return {"allowed": True, "reason": "path_allowed", "path": norm_path}

        # 2. Extract and normalize target host
        norm_host = DomainMatcher.normalize_host(host)

        # 3. Resolve status
        project = self.resolve_status()

        # 4. Domain allowlist check
        effective_domains = (
            self.config.allowed_domains
            if self.config.allowed_domains is not None
            else project.get("allowedDomains")
        )
        if effective_domains is not None and not DomainMatcher.is_domain_allowed(norm_host, effective_domains):
            return {
                "allowed": False,
                "reason": "domain_mismatch",
                "code": "DEVGUARD_DOMAIN_LOCKED",
                "title": "Domain Authorization Required",
                "message": f"The domain '{norm_host}' is not authorized to host this application.",
                "appName": project.get("appName"),
                "contactEmail": project.get("contactEmail"),
                "contactPhone": project.get("contactPhone"),
                "contactWhatsapp": project.get("contactWhatsapp"),
                "host": norm_host,
                "allowedDomains": effective_domains,
                "project": project,
            }

        # 5. Explicit Project Locked check
        status = str(project.get("status", "active")).lower()
        if status in ("locked", "expired"):
            return {
                "allowed": False,
                "reason": "project_locked",
                "code": "DEVGUARD_PROJECT_LOCKED",
                "title": project.get("title") or "Service Temporarily Locked",
                "message": project.get("message") or "This application has been locked by the developer or organization.",
                "appName": project.get("appName"),
                "contactEmail": project.get("contactEmail"),
                "contactPhone": project.get("contactPhone"),
                "contactWhatsapp": project.get("contactWhatsapp"),
                "project": project,
            }

        # 6. Autolock due-date / milestone delinquency check
        due_at = project.get("paymentDueAt") or project.get("dueAt")
        autolock_enabled = (
            not isinstance(project.get("autolock"), dict)
            or project["autolock"].get("enabled") is not False
        )
        if status == "active" and due_at and autolock_enabled:
            autolock_state = project.get("autolockState") or {}
            if autolock_state.get("autoLocked"):
                return {
                    "allowed": False,
                    "reason": "project_delinquent",
                    "code": "DEVGUARD_PROJECT_LOCKED",
                    "title": project.get("title") or "Service Temporarily Suspended",
                    "message": project.get("message") or "This website has been automatically suspended pending invoice settlement.",
                    "appName": project.get("appName"),
                    "contactEmail": project.get("contactEmail"),
                    "contactPhone": project.get("contactPhone"),
                    "contactWhatsapp": project.get("contactWhatsapp"),
                    "project": project,
                }

        return {"allowed": True, "status": "active", "project": project}
