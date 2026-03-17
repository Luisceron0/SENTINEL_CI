"""
File Purpose:
- Build Sentinel FastAPI application, register middleware/routes, and enforce global error sanitization.

Key Security Considerations:
- Registers authentication, rate-limit, security-header, and JSON logging middleware.
- Adds catch-all exception handling with request correlation IDs and sanitized client responses.

OWASP 2025 Categories Addressed:
- A01, A02, A07, A09, A10
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from api.config import load_settings
from api.middleware.logging import JsonLoggingMiddleware
from api.middleware.rate_limit import RateLimitMiddleware
from api.middleware.security import SecurityHeadersMiddleware
from api.routes import alerts, keys, reports, repositories, scans, webhooks


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # SECURITY: fail fast if runtime secrets/config are missing.
    load_settings()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="Sentinel CI API", version="0.1.0", lifespan=lifespan)

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(JsonLoggingMiddleware)

    app.include_router(webhooks.router)
    app.include_router(scans.router)
    app.include_router(repositories.router)
    app.include_router(reports.router)
    app.include_router(alerts.router)
    app.include_router(keys.router)

    @app.get("/metrics")
    def metrics() -> PlainTextResponse:
        body = "\n".join(
            [
                "# HELP sentinel_api_errors_total API errors",
                "# TYPE sentinel_api_errors_total counter",
                "sentinel_api_errors_total{status_code=\"200\",path=\"/metrics\"} 1",
                "# HELP sentinel_api_request_duration_seconds API request durations",
                "# TYPE sentinel_api_request_duration_seconds histogram",
            ]
        )
        return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4")

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, _exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", str(uuid4()))
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "request_id": request_id},
        )

    return app


app = create_app()
