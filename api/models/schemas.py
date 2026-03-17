"""
File Purpose:
- Define strict Pydantic v2 schemas for all Sentinel API request and response contracts.

Key Security Considerations:
- Enforces strict types, bounded lengths, and controlled enum values.
- Blocks malformed and oversized payloads at trust boundaries.

OWASP 2025 Categories Addressed:
- A05, A10
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ACCEPTED = "ACCEPTED"


class AlertStatus(str, Enum):
    SENT = "SENT"
    FAILED = "FAILED"


class FindingIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    scanner: str = Field(min_length=2, max_length=32)
    severity: Severity
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3, max_length=5000)
    file_path: str | None = Field(default=None, max_length=1000)
    line_start: int | None = Field(default=None, ge=1, le=2_000_000)
    line_end: int | None = Field(default=None, ge=1, le=2_000_000)
    cve_id: str | None = Field(default=None, max_length=50)
    cwe_id: str | None = Field(default=None, max_length=50)
    remediation: str = Field(min_length=3, max_length=5000)
    false_positive: bool = False
    status: FindingStatus = FindingStatus.OPEN
    idempotency_key: str = Field(min_length=32, max_length=128)


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    repository_id: UUID
    repository_name: str = Field(min_length=3, max_length=300)
    commit_sha: str = Field(min_length=7, max_length=64)
    branch: str = Field(min_length=1, max_length=200)
    trigger_event: str = Field(min_length=2, max_length=50)
    scanner_versions: dict[str, str] = Field(default_factory=dict)
    findings: list[FindingIn] = Field(default_factory=list, max_length=5000)
    sbom_document: dict[str, Any]


class ScanOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    scan_id: UUID
    findings_count: int
    critical_count: int
    dashboard_url: str


class RepositoryCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    full_name: str = Field(min_length=3, max_length=300)

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        if value.count("/") != 1:
            raise ValueError("repository must use owner/repo format")
        return value.lower()


class RepositoryOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: UUID
    owner_id: UUID
    full_name: str
    default_branch: str
    created_at: datetime


class WebhookCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    repository_id: UUID
    url: HttpUrl
    minimum_severity: Severity = Severity.HIGH


class WebhookOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: UUID
    repository_id: UUID
    url: str
    minimum_severity: Severity
    active: bool


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: UUID
    prefix: str
    key: str


class ErrorOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    error: str
    message: str
    request_id: str
