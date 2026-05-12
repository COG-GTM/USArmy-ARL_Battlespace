"""Pytest configuration for the security-audit test suite.

The repository ships a top-level ``__init__.py`` that imports the entire
codebase eagerly. Pytest's rootdir-based collection would otherwise drag
that import in (and fail under Python 3.10+ because of a pre-existing
``from collections import Set`` in ``src/StateModule.py``), even though
the compliance tests themselves only read files on disk.

Adding ``tests/`` as the import root scopes pytest to this directory and
avoids collecting the repo-level ``__init__.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTS_DIR.parent

# Allow tests to import the dedicated security_audit_logging module without
# pulling in the rest of the codebase (which depends on game/UI modules
# that are not relevant to the audit).
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
