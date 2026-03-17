"""
File Purpose:
- Validate untrusted user input helpers, including SSRF-safe webhook URL validation.

Key Security Considerations:
- Rejects insecure URL schemes and private/internal address ranges.
- Applies centralized validation function across all webhook ingestion points.

OWASP 2025 Categories Addressed:
- A01, A05, A10
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def validate_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("webhook URL must use HTTPS")
    if not parsed.hostname:
        raise ValueError("webhook URL must include a hostname")

    host = parsed.hostname
    try:
        ip_obj = ipaddress.ip_address(host)
        if _is_private_or_local(ip_obj):
            raise ValueError("webhook URL must not target private or local addresses")
        return url
    except ValueError:
        # host is not a literal IP, resolve DNS
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise ValueError("webhook URL hostname could not be resolved") from exc

        for info in infos:
            address = info[4][0]
            ip_obj = ipaddress.ip_address(address)
            if _is_private_or_local(ip_obj):
                raise ValueError("webhook URL resolves to private or local address") from None

    return url


def _is_private_or_local(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )
