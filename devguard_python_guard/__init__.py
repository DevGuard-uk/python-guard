"""DevGuard Python Guard Package.

Zero-dependency anti-theft, domain authorization, milestone autolock,
and SEO-safe HTTP 503 lockouts for FastAPI, Starlette, Django, and Flask.
"""

from .core import (
    DevGuard,
    DevGuardConfig,
    DomainMatcher,
    LockResponse,
)
from .asgi import DevGuardASGIMiddleware
from .wsgi import DevGuardWSGIMiddleware

__version__ = "1.0.1"

__all__ = [
    "DevGuard",
    "DevGuardConfig",
    "DomainMatcher",
    "LockResponse",
    "DevGuardASGIMiddleware",
    "DevGuardWSGIMiddleware",
    "__version__",
]
