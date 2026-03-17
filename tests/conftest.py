"""
File Purpose:
- Ensure test runtime can import project modules from repository root.

Key Security Considerations:
- Prevents ambiguous import resolution during security test execution.

OWASP 2025 Categories Addressed:
- A06, A10
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
