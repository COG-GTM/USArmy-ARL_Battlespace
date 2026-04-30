"""Secure network message envelope (Wave 3 CWE-502 remediation).

Replaces untrusted ``pickle.loads`` / ``dill.loads`` deserialization of bytes
received over TCP sockets with a JSON-schema + HMAC-signed envelope. Deserializing
attacker-controlled pickle data is CWE-502 (Deserialization of Untrusted Data) and
is explicitly forbidden by STIG V-220631 / V-220632 (input validation / sanitization),
NIST 800-53 SI-10 (input validation), SC-8 (transmission integrity), and SC-28
(protection of data at rest / in transit).

Wire format (all bytes, big-endian where relevant)::

    [ 8-byte length prefix (uint64) ] [ body_json_utf8 ] b'.' [ hmac_sha256_hex_utf8 ]

``body_json_utf8`` is a canonical JSON object with keys ``ts`` (unix seconds),
``nonce`` (16-byte hex), and ``payload`` (the caller-provided dict). The signature
covers the exact ``body_json_utf8`` bytes so any tamper of ts/nonce/payload is
detected before JSON parsing or schema validation runs.

Public API
----------
``wrap(payload, secret)``          — build signed envelope bytes.
``unwrap(blob, secret, schema)``   — verify HMAC (constant-time), check replay
                                      window, validate against JSON Schema, return
                                      the payload dict.
``to_jsonable(obj)``               — best-effort coercion of arbitrary Python
                                      objects to JSON-safe primitives. Used at
                                      wrap time only — the unwrap side never
                                      executes code regardless of how the wire
                                      payload was constructed.
``shared_secret()``                — read ``BATTLESPACE_AGENT_SECRET`` env var,
                                      falling back to a hard-coded dev secret (see
                                      SECURITY.md rotation runbook).
``EnvelopeError``                  — raised on any failure (signature mismatch,
                                      schema failure, malformed frame, replay).

The module is intentionally *strict* and *pure* — no pickle, no eval, no code
execution paths on the receive side.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import secrets
import time
from typing import Any, Mapping

from jsonschema import ValidationError, validate

__all__ = [
    "EnvelopeError",
    "wrap",
    "unwrap",
    "to_jsonable",
    "shared_secret",
    "DEFAULT_REPLAY_WINDOW_SECONDS",
    "pack",
    "unpack",
]


DEFAULT_REPLAY_WINDOW_SECONDS = 30
_LENGTH_PREFIX_BYTES = 8
_MAX_FRAME_BYTES = 16 * 1024 * 1024  # 16 MiB; defensive upper bound
_SHARED_SECRET_ENV = "BATTLESPACE_AGENT_SECRET"

# TODO: rotate via SECRETS_MANAGER — see SECURITY.md, "HMAC key rotation runbook".
# This default value is for local development only; production deployments must
# export BATTLESPACE_AGENT_SECRET before launching any server or client process.
_DEV_FALLBACK_SECRET = b"battlespace-dev-only-shared-secret-change-me"


class EnvelopeError(Exception):
    """Raised on any envelope verification / validation failure."""


def shared_secret() -> bytes:
    """Return the HMAC shared secret bytes.

    Reads ``BATTLESPACE_AGENT_SECRET`` from the environment if set, else returns
    a hard-coded development value. Production deployments MUST set the env var
    per the rotation runbook in ``SECURITY.md``.
    """

    value = os.environ.get(_SHARED_SECRET_ENV)
    if value:
        return value.encode("utf-8")
    return _DEV_FALLBACK_SECRET


def to_jsonable(obj: Any) -> Any:
    """Recursively coerce ``obj`` into JSON-safe primitives.

    Primitive JSON types (str, int, float, bool, None) pass through. Lists,
    tuples, sets, frozensets become lists of converted items. Dicts are
    converted with keys coerced to strings. Everything else — class objects,
    functions, instances of user-defined classes — is converted to a marker
    dict of the form ``{"__type__": "<ClassName>", ...}`` so that the wire
    payload stays strictly JSON and no code executes during deserialization.
    """

    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return {"__type__": "bytes", "hex": bytes(obj).hex()}
    if isinstance(obj, Mapping):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, type):
        return {"__type__": "class", "name": obj.__name__}
    if callable(obj):
        return {"__type__": "callable", "name": getattr(obj, "__name__", repr(obj))}
    inst_dict = getattr(obj, "__dict__", None)
    if isinstance(inst_dict, dict):
        return {
            "__type__": type(obj).__name__,
            **{str(k): to_jsonable(v) for k, v in inst_dict.items()},
        }
    return {"__type__": type(obj).__name__, "__repr__": repr(obj)}


def wrap(payload: Mapping[str, Any], secret: bytes, *, now: float | None = None) -> bytes:
    """Build a length-prefixed HMAC-SHA256 signed JSON envelope.

    Parameters
    ----------
    payload:
        Dict to transmit. Must already be JSON-serializable (use
        :func:`to_jsonable` at the call site to coerce mixed Python objects).
    secret:
        Shared HMAC key bytes. Callers should obtain this from
        :func:`shared_secret`.
    now:
        Optional override for the timestamp (seconds since epoch). Primarily
        for tests.
    """

    if not isinstance(payload, Mapping):
        raise EnvelopeError("payload must be a mapping / dict")
    if not isinstance(secret, (bytes, bytearray)):
        raise EnvelopeError("secret must be bytes")

    try:
        payload_json = json.loads(json.dumps(payload))
    except (TypeError, ValueError) as exc:
        raise EnvelopeError(f"payload is not JSON-serializable: {exc}") from exc

    body = {
        "ts": int(now if now is not None else time.time()),
        "nonce": secrets.token_hex(16),
        "payload": payload_json,
    }
    body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_hex = hmac.new(bytes(secret), body_bytes, hashlib.sha256).hexdigest().encode("ascii")
    framed = body_bytes + b"." + sig_hex
    if len(framed) > _MAX_FRAME_BYTES:
        raise EnvelopeError("frame exceeds maximum size")
    return len(framed).to_bytes(_LENGTH_PREFIX_BYTES, "big") + framed


def unwrap(
    blob: bytes,
    secret: bytes,
    schema: Mapping[str, Any],
    *,
    replay_window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
    now: float | None = None,
) -> dict:
    """Verify and parse an envelope produced by :func:`wrap`.

    Performs, in order:

    1. Length-prefix bounds check.
    2. HMAC-SHA256 verification via :func:`hmac.compare_digest`.
    3. Strict JSON parse of the body.
    4. Replay-window rejection: ``abs(now - body.ts) > replay_window_seconds``
       raises :class:`EnvelopeError`.
    5. JSON-Schema validation of ``payload`` using ``jsonschema.validate``.

    Any failure raises :class:`EnvelopeError`. No pickle, no eval, no code path
    that could execute attacker-controlled bytes.
    """

    if not isinstance(blob, (bytes, bytearray)):
        raise EnvelopeError("blob must be bytes")
    if not isinstance(secret, (bytes, bytearray)):
        raise EnvelopeError("secret must be bytes")
    if not isinstance(schema, Mapping):
        raise EnvelopeError("schema must be a mapping / dict")

    if len(blob) < _LENGTH_PREFIX_BYTES:
        raise EnvelopeError("frame too short for length prefix")
    framed_len = int.from_bytes(bytes(blob[:_LENGTH_PREFIX_BYTES]), "big")
    if framed_len <= 0 or framed_len > _MAX_FRAME_BYTES:
        raise EnvelopeError("frame length out of bounds")

    framed = bytes(blob[_LENGTH_PREFIX_BYTES : _LENGTH_PREFIX_BYTES + framed_len])
    if len(framed) != framed_len:
        raise EnvelopeError("truncated frame")

    try:
        body_bytes, sig_hex = framed.rsplit(b".", 1)
    except ValueError as exc:
        raise EnvelopeError("frame missing signature delimiter") from exc

    expected_hex = hmac.new(bytes(secret), body_bytes, hashlib.sha256).hexdigest().encode("ascii")
    if not hmac.compare_digest(expected_hex, sig_hex):
        raise EnvelopeError("HMAC signature mismatch")

    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"malformed body JSON: {exc}") from exc

    if not isinstance(body, dict) or "ts" not in body or "payload" not in body or "nonce" not in body:
        raise EnvelopeError("body missing required envelope fields")
    if not isinstance(body["ts"], int):
        raise EnvelopeError("body.ts must be an integer")

    current = int(now if now is not None else time.time())
    if abs(current - body["ts"]) > replay_window_seconds:
        raise EnvelopeError("timestamp outside replay window")

    payload = body["payload"]
    try:
        validate(instance=payload, schema=dict(schema))
    except ValidationError as exc:
        raise EnvelopeError(f"schema validation failed: {exc.message}") from exc

    if not isinstance(payload, dict):
        raise EnvelopeError("payload must be a JSON object")
    return payload


# ----------------------------------------------------------------------------
# Convenience wrappers used at call sites that need to send/receive non-dict
# Python values (lists, strings, ints). ``pack`` always emits a dict-shaped
# payload so the strict envelope format holds; ``unpack`` reverses it.
# ----------------------------------------------------------------------------

_VALUE_KEY = "__wave3_value__"
_PACK_SCHEMA = {"type": "object"}


def pack(obj: Any, secret: bytes) -> bytes:
    """Wrap an arbitrary Python value (dict or not) into a signed envelope.

    Dicts are coerced via :func:`to_jsonable` and passed through. Non-dict
    values are wrapped under the key ``__wave3_value__`` so the on-wire payload
    is always a JSON object. Use :func:`unpack` on the receive side to get the
    original value back.
    """

    safe = to_jsonable(obj)
    if not isinstance(safe, dict):
        safe = {_VALUE_KEY: safe}
    return wrap(safe, secret)


def unpack(blob: bytes, secret: bytes, schema: Mapping[str, Any] | None = None) -> Any:
    """Inverse of :func:`pack`. Returns the original value (dict or not).

    ``schema`` defaults to a permissive ``{"type": "object"}`` — call sites
    that want stricter validation should pass an explicit JSON Schema.
    """

    payload = unwrap(blob, secret, schema if schema is not None else _PACK_SCHEMA)
    if set(payload.keys()) == {_VALUE_KEY}:
        return payload[_VALUE_KEY]
    return payload
