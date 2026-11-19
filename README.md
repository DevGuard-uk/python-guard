# DevGuard Python Guard (`devguard-python-guard`)

Official zero-dependency Python guard for **DevGuard** anti-theft protection, domain allowlisting, invoice milestone autolock enforcement, and SEO-safe HTTP 503 lockouts.

Supports **FastAPI**, **Starlette** (ASGI), **Django**, and **Flask** (WSGI).

---

## Key Features

- **Zero External Dependencies**: Operates exclusively using the Python Standard Library (`urllib`, `json`, `re`, `time`, `threading`).
- **Fail-Safe Open Policy**: Network timeouts, DNS issues, or unreachable APIs will **never** interrupt client application traffic.
- **Domain Authorization**: Enforces authorized hosting domains with support for wildcard subdomains (`*.example.com`).
- **Milestone Autolock**: Automatically queries project status from the DevGuard API with local in-memory TTL caching.
- **SEO-Safe HTTP 503**: Emits HTTP status 503 with `Retry-After: 3600` so search crawlers do not drop site ranking during payment disputes.

---

## Installation

```bash
pip install devguard-python-guard
```

---

## Usage

### 1. FastAPI / Starlette (ASGI)

```python
from fastapi import FastAPI
from devguard_python_guard import DevGuardASGIMiddleware

app = FastAPI()

app.add_middleware(
    DevGuardASGIMiddleware,
    project_id="proj_your_project_id",
    allowed_domains=["example.com", "*.example.com"],
    fail_safe=True,  # Default: True (fail-safe open)
    cache_ttl=300,   # 5-minute status cache
)

@app.get("/")
def home():
    return {"message": "Hello World"}
```

### 2. Django (WSGI)

In `myproject/wsgi.py`:

```python
import os
from django.core.wsgi import get_wsgi_application
from devguard_python_guard import DevGuardWSGIMiddleware

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')

application = get_wsgi_application()
application = DevGuardWSGIMiddleware(
    application,
    project_id=os.getenv("DEVGUARD_PROJECT_ID"),
    allowed_domains=["example.com", "*.example.com"],
    fail_safe=True,
)
```

### 3. Flask (WSGI)

```python
from flask import Flask
from devguard_python_guard import DevGuardWSGIMiddleware

app = Flask(__name__)
app.wsgi_app = DevGuardWSGIMiddleware(
    app.wsgi_app,
    project_id="proj_your_project_id",
    allowed_domains=["example.com", "*.example.com"],
    fail_safe=True,
)

@app.route("/")
def index():
    return "Hello Flask"
```

---

## Environment Variables

You can configure DevGuard via environment variables or explicitly in code:

| Variable | Description | Default |
|---|---|---|
| `DEVGUARD_PROJECT_ID` | Project ID from DevGuard dashboard | `""` |
| `DEVGUARD_API_URL` | DevGuard API endpoint | `https://api.devguard.uk` |
| `DEVGUARD_API_KEY` | DevGuard API key (optional) | `None` |
| `DEVGUARD_ALLOWED_DOMAINS` | Comma-separated allowed domains | `None` |
| `DEVGUARD_FAIL_SAFE` | `open` (true) or `closed` (false) | `open` |
| `DEVGUARD_CACHE_TTL` | Cache duration in seconds | `300` |
| `DEVGUARD_TRUST_PROXY` | Trust `X-Forwarded-Host` | `false` |
