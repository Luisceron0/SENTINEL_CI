"""
File Purpose:
- Enforce API rate limits and authentication abuse controls.

Key Security Considerations:
- Blocks brute-force and credential-stuffing attempts.
- Applies strict thresholds with deterministic HTTP 429 responses.

OWASP 2025 Categories Addressed:
- A07, A09, A10
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class RateLimitMiddleware(BaseHTTPMiddleware):
    _MAX_TRACKED_KEYS = 10_000

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._events: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        ip = _extract_client_ip(request)
        now = time.time()

        # SECURITY: auth failures are tracked with a tighter bucket.
        request.state.client_ip = ip
        request.state.auth_failed = False

        _prune_store(self._events, now, window_seconds=300, max_keys=self._MAX_TRACKED_KEYS)

        if _is_general_limit_exceeded(self._events, f"general:{ip}", now, 60, 60):
            return Response(
                content='{"error":"rate_limited","message":"Too many requests","request_id":""}',
                status_code=429,
                media_type="application/json",
            )

        response = await call_next(request)

        if response.status_code == 401:
            request.state.auth_failed = True
            if _is_general_limit_exceeded(self._events, f"auth:{ip}", now, 60, 5):
                return Response(
                    content='{"error":"auth_rate_limited","message":"Too many failed auth attempts","request_id":""}',
                    status_code=429,
                    media_type="application/json",
                )

        return response


def _is_general_limit_exceeded(
    store: dict[str, deque[float]],
    key: str,
    now: float,
    window_seconds: int,
    max_events: int,
) -> bool:
    bucket = store[key]
    while bucket and (now - bucket[0]) > window_seconds:
        bucket.popleft()
    bucket.append(now)
    return len(bucket) > max_events


def _extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        value = forwarded.split(",")[0].strip()
        return str(value)
    if request.client and request.client.host:
        return str(request.client.host)
    return "unknown"


def _prune_store(
    store: dict[str, deque[float]],
    now: float,
    window_seconds: int,
    max_keys: int,
) -> None:
    if len(store) <= max_keys:
        return

    stale_keys = [k for k, bucket in store.items() if not bucket or (now - bucket[-1]) > window_seconds]
    for key in stale_keys:
        store.pop(key, None)
