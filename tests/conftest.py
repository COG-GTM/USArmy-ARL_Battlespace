"""Pytest bootstrap for Wave 3 secure_envelope tests.

Adds ``<repo>/src`` to ``sys.path`` so ``import secure_envelope`` works regardless
of how pytest is invoked, and isolates this tests/ tree from the repo-root
``__init__.py`` (which imports legacy game modules that do not load on modern
Python).
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.normpath(os.path.join(HERE, "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)
