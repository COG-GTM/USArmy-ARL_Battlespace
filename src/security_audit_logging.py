"""Structured security logger for ARL Battlespace.

This module provides a single configured ``logging.Logger`` used by the
security-relevant code paths in ServerWithUI.py, HumanInterface.py,
RemoteAgent.py, reliableSockets.py, and src/Fully_Visible_UI/*.

It exists because the rest of the codebase emits diagnostics via bare
``print()`` (no level, no timestamp, no machine-parseable format), which
prevents aggregation to a SIEM and does not satisfy DISA STIG V-222423..
V-222428 / NIST AU-2, AU-3, AU-9.

A full ``print -> logging`` conversion across the repo is a deferred
architectural change (see ``docs/security-audit/TRIAGE_REPORT.md``).
This module is the in-PR foothold: it is wired into the new
``MAX_MESSAGE_SIZE`` enforcement in ``_safe_unpickle()``, into the
newly-narrowed ``except`` clauses, and into the protocol-handshake
error paths.

Constants
---------
``MAX_MESSAGE_SIZE`` (int) -- 1 MiB upper bound on a single recv()
payload before it is handed to dill/pickle. Configurable via the
``ARL_BATTLESPACE_MAX_MESSAGE_SIZE`` environment variable.

Usage
-----
::

    from security_audit_logging import get_security_logger, safe_unpickle
    log = get_security_logger(__name__)
    obj = safe_unpickle(raw_bytes, source='ServerWithUI.initPositions')

DISA STIG: V-222423..V-222428 (audit records)
NIST 800-53 r5: AU-2 (event types), AU-3 (content), AU-9 (protection)
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

_LOGGER_CACHE: dict[str, logging.Logger] = {}


def _default_max_size() -> int:
    """Return the configured maximum recv() payload size in bytes."""
    raw = os.environ.get("ARL_BATTLESPACE_MAX_MESSAGE_SIZE", "")
    if raw.isdigit():
        return int(raw)
    return 1 << 20  # 1 MiB


MAX_MESSAGE_SIZE: int = _default_max_size()
"""Upper bound on a single recv() payload accepted by ``safe_unpickle``."""


def get_security_logger(name: str = "arl_battlespace.security") -> logging.Logger:
    """Return a configured logger for security-relevant events.

    The returned logger writes timestamped, levelled records to ``stderr``
    and is safe to call from any module. Multiple calls with the same
    name return the same logger (per stdlib ``logging`` semantics) and
    do NOT duplicate handlers.
    """
    cached = _LOGGER_CACHE.get(name)
    if cached is not None:
        return cached

    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stderr)
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(
            os.environ.get("ARL_BATTLESPACE_LOG_LEVEL", "INFO").upper()
        )
        logger.propagate = False

    _LOGGER_CACHE[name] = logger
    return logger


class UnpickleError(ValueError):
    """Raised when a payload is rejected before dill/pickle.loads runs.

    Used to surface size-cap violations, type errors, and structural
    rejections distinctly from genuine deserialization failures.
    """


def safe_unpickle(data: bytes, *, source: str = "unknown") -> Any:
    """Validate size, then deserialize via dill/pickle.

    Parameters
    ----------
    data:
        Raw bytes returned by ``socket.recv``. Validated before
        deserialization runs.
    source:
        Human-readable label of the call site (e.g. ``"ServerWithUI:199"``).
        Logged on any failure so SIEM aggregation can locate the call site.

    Returns
    -------
    The deserialized Python object.

    Raises
    ------
    UnpickleError:
        If ``data`` is empty, not ``bytes``/``bytearray``, or exceeds
        ``MAX_MESSAGE_SIZE``.
    Exception:
        Any exception raised by ``dill.loads`` is re-raised after being
        logged at ``ERROR`` level with the ``source`` label attached.

    Notes
    -----
    THIS DOES NOT MAKE DILL DESERIALIZATION SAFE. dill.loads will still
    execute the ``__reduce__`` method of any object in the payload, and a
    crafted payload below ``MAX_MESSAGE_SIZE`` can still achieve RCE.
    The architectural fix is to replace the wire protocol with a
    schema-validated format (see docs/security-audit/SECURITY.md and the
    deferred Jira sub-tasks).

    This helper exists to (a) reject obviously-malformed oversize blobs
    before they enter the dill state machine, and (b) record each
    deserialization attempt in a machine-parseable audit log.
    """
    log = get_security_logger()
    if not isinstance(data, (bytes, bytearray)):
        log.error("safe_unpickle: non-bytes input at %s type=%s", source, type(data).__name__)
        raise UnpickleError(f"non-bytes input from {source}")
    size = len(data)
    if size == 0:
        log.warning("safe_unpickle: empty payload at %s", source)
        raise UnpickleError(f"empty payload from {source}")
    if size > MAX_MESSAGE_SIZE:
        log.error(
            "safe_unpickle: oversize payload at %s size=%d max=%d -- REJECTED",
            source, size, MAX_MESSAGE_SIZE,
        )
        raise UnpickleError(
            f"payload from {source} of {size} bytes exceeds MAX_MESSAGE_SIZE={MAX_MESSAGE_SIZE}"
        )

    import dill  # noqa: PLC0415 -- local import keeps this module free of dill at import time
    try:
        obj = dill.loads(bytes(data))
    except Exception as exc:  # pylint: disable=broad-except
        log.error("safe_unpickle: dill.loads failed at %s type=%s", source, type(exc).__name__)
        raise

    log.debug("safe_unpickle: ok at %s size=%d type=%s", source, size, type(obj).__name__)
    return obj


__all__ = [
    "MAX_MESSAGE_SIZE",
    "UnpickleError",
    "get_security_logger",
    "safe_unpickle",
]
