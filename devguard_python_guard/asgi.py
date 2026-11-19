"""ASGI Middleware for DevGuard (FastAPI, Starlette).

Zero-dependency ASGI HTTP middleware enforcing domain authorization,
milestone autolock delinquency, and SEO-safe HTTP 503 lockouts.
"""

import json
from typing import Any, Callable, Dict, Optional
from .core import DevGuard, DevGuardConfig, LockResponse


class DevGuardASGIMiddleware:
    """ASGI Middleware compatible with FastAPI and Starlette."""

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

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        # Only intercept standard HTTP requests
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # 1. Extract path
        path = scope.get("path") or "/"

        # 2. Extract headers
        headers_dict: Dict[str, str] = {}
        for raw_k, raw_v in scope.get("headers", []):
            try:
                k = raw_k.decode("latin1").lower()
                v = raw_v.decode("latin1")
                headers_dict[k] = v
            except Exception:
                pass

        # 3. Resolve host
        host = ""
        if self.guard.config.trust_proxy and "x-forwarded-host" in headers_dict:
            host = headers_dict["x-forwarded-host"].split(",")[0].strip()
        elif "host" in headers_dict:
            host = headers_dict["host"]

        # 4. Check authorization
        result = self.guard.check_request(host=host, path=path)

        if result.get("allowed"):
            await self.app(scope, receive, send)
            return

        # 5. Handle locked state (SEO-safe HTTP 503)
        wants_json = "application/json" in headers_dict.get("accept", "").lower()

        if wants_json:
            payload = LockResponse.render_json(result)
            body = json.dumps(payload, indent=2).encode("utf-8")
            content_type = b"application/json; charset=utf-8"
        else:
            body = LockResponse.render_html(result).encode("utf-8")
            content_type = b"text/html; charset=utf-8"

        reason = str(result.get("reason", "project_locked")).encode("latin1", "ignore")

        response_headers = [
            (b"content-type", content_type),
            (b"content-length", str(len(body)).encode("latin1")),
            (b"retry-after", b"3600"),
            (b"cache-control", b"no-store, no-cache, must-revalidate"),
            (b"x-devguard-status", b"locked"),
            (b"x-devguard-reason", reason),
        ]

        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": response_headers,
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })
