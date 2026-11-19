"""WSGI Middleware for DevGuard (Django, Flask).

Zero-dependency WSGI HTTP middleware enforcing domain authorization,
milestone autolock delinquency, and SEO-safe HTTP 503 lockouts.
"""

import json
from typing import Any, Callable, Dict, List, Optional, Tuple
from .core import DevGuard, DevGuardConfig, LockResponse


class DevGuardWSGIMiddleware:
    """WSGI Middleware compatible with Django, Flask, and standard WSGI servers."""

    def __init__(
        self,
        app: Any,
        config: Optional[DevGuardConfig] = None,
        **kwargs,
    ):
        self.app = app
        if config is not None:
            self.guard = DevGuard(config)
        else:
            self.guard = DevGuard(DevGuardConfig(**kwargs))

    def __call__(self, environ: Dict[str, Any], start_response: Callable) -> List[bytes]:
        # 1. Extract path
        path = environ.get("PATH_INFO") or "/"

        # 2. Resolve host
        host = ""
        if self.guard.config.trust_proxy and "HTTP_X_FORWARDED_HOST" in environ:
            host = environ["HTTP_X_FORWARDED_HOST"].split(",")[0].strip()
        elif "HTTP_HOST" in environ:
            host = environ["HTTP_HOST"]
        elif "SERVER_NAME" in environ:
            host = environ["SERVER_NAME"]

        # 3. Check authorization
        result = self.guard.check_request(host=host, path=path)

        if result.get("allowed"):
            return self.app(environ, start_response)

        # 4. Handle locked state (SEO-safe HTTP 503)
        wants_json = "application/json" in environ.get("HTTP_ACCEPT", "").lower()

        if wants_json:
            payload = LockResponse.render_json(result)
            body = json.dumps(payload, indent=2).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        else:
            body = LockResponse.render_html(result).encode("utf-8")
            content_type = "text/html; charset=utf-8"

        reason = str(result.get("reason", "project_locked"))

        response_headers: List[Tuple[str, str]] = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("Retry-After", "3600"),
            ("Cache-Control", "no-store, no-cache, must-revalidate"),
            ("X-DevGuard-Status", "locked"),
            ("X-DevGuard-Reason", reason),
        ]

        start_response("503 Service Unavailable", response_headers)
        return [body]
