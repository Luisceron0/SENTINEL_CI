"""
File Purpose:
- Emit structured JSON logs for requests, auth events, scan events, and errors.

Key Security Considerations:
- Redacts sensitive values and hashes user identifiers.
- Emits warning signal for potential credential stuffing activity.

OWASP 2025 Categories Addressed:
- A09, A10
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from api.utils.crypto import hash_user_identifier

logger = logging.getLogger("sentinel.api")
logger.setLevel(logging.INFO)


class JsonLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.auth_401_windows: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        started = time.perf_counter()
        request_id = str(uuid4())
        request.state.request_id = request_id

        response = await call_next(request)

        duration_ms = int((time.perf_counter() - started) * 1000)
        ip = _sanitize_ip(getattr(request.state, "client_ip", "unknown"))
        identity = getattr(request.state, "identity", None)

        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "request_id": request_id,
            "event_type": "api_request",
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "user_id": hash_user_identifier(str(identity.user_id)) if identity and identity.user_id else None,
            "repository_id": None,
            "ip_address": ip,
        }
        logger.info(json.dumps(payload, separators=(",", ":")))

        if response.status_code == 401:
            if self._credential_stuffing_detected(ip):
                warning = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "request_id": request_id,
                    "event_type": "potential_credential_stuffing",
                    "status_code": 401,
                    "ip_address": ip,
                    "level": "WARNING",
                }
                logger.warning(json.dumps(warning, separators=(",", ":")))

        return response

    def _credential_stuffing_detected(self, ip: str) -> bool:
        now = time.time()
        bucket = self.auth_401_windows[ip]
        while bucket and (now - bucket[0]) > 300:
            bucket.popleft()
        bucket.append(now)
        return len(bucket) >= 10


def _sanitize_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["0"])
    return ip
