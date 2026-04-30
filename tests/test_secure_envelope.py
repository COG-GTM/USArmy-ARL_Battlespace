"""Unit tests for src.secure_envelope (Wave 3 CWE-502 remediation).

Covers:
* Round-trip wrap/unwrap with schema validation.
* HMAC signature rejection on tamper.
* Schema mismatch rejection.
* Replay-window rejection for stale timestamps.
* Frame-level errors (truncation, missing delimiter, bad length prefix).
* ``to_jsonable`` coercion of common Python object shapes.
"""

from __future__ import annotations

import os
import sys

import pytest

# Make ``src`` importable both via ``pytest`` from repo root and directly.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from secure_envelope import (  # noqa: E402
    DEFAULT_REPLAY_WINDOW_SECONDS,
    EnvelopeError,
    pack,
    shared_secret,
    to_jsonable,
    unpack,
    unwrap,
    wrap,
)


SECRET = b"unit-test-hmac-secret-key"
BROAD_SCHEMA = {"type": "object"}
STRICT_SCHEMA = {
    "type": "object",
    "properties": {"contents": {"type": "string"}, "data": {"type": "integer"}},
    "required": ["contents", "data"],
    "additionalProperties": False,
}


def test_roundtrip_returns_original_payload():
    payload = {"contents": "PlayerID", "data": 2}
    blob = wrap(payload, SECRET)
    assert isinstance(blob, bytes)
    assert unwrap(blob, SECRET, STRICT_SCHEMA) == payload


def test_roundtrip_with_broad_schema_permits_arbitrary_object():
    payload = {"nested": {"a": [1, 2, 3]}, "flag": True}
    blob = wrap(payload, SECRET)
    assert unwrap(blob, SECRET, BROAD_SCHEMA) == payload


def test_bad_signature_is_rejected():
    blob = bytearray(wrap({"contents": "PlayerID", "data": 1}, SECRET))
    # Flip one bit inside the hex signature (the last byte of the frame).
    blob[-1] ^= 0x01
    with pytest.raises(EnvelopeError, match="signature mismatch"):
        unwrap(bytes(blob), SECRET, STRICT_SCHEMA)


def test_tampered_body_is_rejected():
    blob = bytearray(wrap({"contents": "PlayerID", "data": 1}, SECRET))
    # Flip a bit in the middle of the body (avoiding the length prefix).
    blob[20] ^= 0x01
    with pytest.raises(EnvelopeError):
        unwrap(bytes(blob), SECRET, STRICT_SCHEMA)


def test_wrong_secret_is_rejected():
    blob = wrap({"contents": "PlayerID", "data": 1}, SECRET)
    with pytest.raises(EnvelopeError, match="signature mismatch"):
        unwrap(blob, b"different-secret", STRICT_SCHEMA)


def test_schema_mismatch_is_rejected():
    # "data" must be integer per STRICT_SCHEMA; send a string.
    blob = wrap({"contents": "PlayerID", "data": "not-an-int"}, SECRET)
    with pytest.raises(EnvelopeError, match="schema validation failed"):
        unwrap(blob, SECRET, STRICT_SCHEMA)


def test_schema_additional_property_rejected():
    blob = wrap({"contents": "X", "data": 1, "extra": True}, SECRET)
    with pytest.raises(EnvelopeError, match="schema validation failed"):
        unwrap(blob, SECRET, STRICT_SCHEMA)


def test_replay_window_rejects_stale_timestamp():
    # Freeze ts far in the past; unwrap with ``now`` set to present should raise.
    stale_blob = wrap({"contents": "X", "data": 1}, SECRET, now=1_000_000)
    with pytest.raises(EnvelopeError, match="replay window"):
        unwrap(
            stale_blob,
            SECRET,
            STRICT_SCHEMA,
            now=1_000_000 + DEFAULT_REPLAY_WINDOW_SECONDS + 5,
        )


def test_replay_window_allows_within_window():
    stale_blob = wrap({"contents": "X", "data": 1}, SECRET, now=1_000_000)
    # Inside window -> succeeds.
    assert unwrap(
        stale_blob,
        SECRET,
        STRICT_SCHEMA,
        now=1_000_000 + DEFAULT_REPLAY_WINDOW_SECONDS - 1,
    ) == {"contents": "X", "data": 1}


def test_future_timestamp_also_rejected():
    # Clock skew in the other direction must also fail.
    blob = wrap({"contents": "X", "data": 1}, SECRET, now=2_000_000)
    with pytest.raises(EnvelopeError, match="replay window"):
        unwrap(
            blob,
            SECRET,
            STRICT_SCHEMA,
            now=2_000_000 - DEFAULT_REPLAY_WINDOW_SECONDS - 5,
        )


def test_truncated_frame_is_rejected():
    blob = wrap({"contents": "X", "data": 1}, SECRET)
    with pytest.raises(EnvelopeError):
        unwrap(blob[:16], SECRET, STRICT_SCHEMA)


def test_short_blob_is_rejected():
    with pytest.raises(EnvelopeError, match="frame too short"):
        unwrap(b"\x00\x00\x00", SECRET, STRICT_SCHEMA)


def test_non_bytes_blob_is_rejected():
    with pytest.raises(EnvelopeError, match="blob must be bytes"):
        unwrap("not-bytes", SECRET, STRICT_SCHEMA)  # type: ignore[arg-type]


def test_non_dict_payload_is_rejected_at_wrap():
    with pytest.raises(EnvelopeError, match="mapping"):
        wrap([1, 2, 3], SECRET)  # type: ignore[arg-type]


def test_non_bytes_secret_is_rejected_at_wrap():
    with pytest.raises(EnvelopeError, match="secret"):
        wrap({"a": 1}, "not-bytes")  # type: ignore[arg-type]


def test_nonces_differ_between_wraps():
    a = wrap({"contents": "X", "data": 1}, SECRET)
    b = wrap({"contents": "X", "data": 1}, SECRET)
    # Same payload produces distinct envelopes (nonce + possibly different ts).
    assert a != b


def test_to_jsonable_primitives_pass_through():
    assert to_jsonable(None) is None
    assert to_jsonable(True) is True
    assert to_jsonable(42) == 42
    assert to_jsonable(3.14) == 3.14
    assert to_jsonable("hello") == "hello"


def test_to_jsonable_converts_collections():
    result = to_jsonable({"tuple": (1, 2), "set": {1, 2}, "frozen": frozenset([3])})
    assert result["tuple"] == [1, 2]
    assert sorted(result["set"]) == [1, 2]
    assert sorted(result["frozen"]) == [3]


def test_to_jsonable_handles_class_objects():
    class Example:
        pass

    result = to_jsonable(Example)
    assert result == {"__type__": "class", "name": "Example"}


def test_to_jsonable_handles_instances():
    class UnitStub:
        def __init__(self):
            self.Owner = 2
            self.Position = (1, 2, 3)

    out = to_jsonable(UnitStub())
    assert out["__type__"] == "UnitStub"
    assert out["Owner"] == 2
    assert out["Position"] == [1, 2, 3]


def test_to_jsonable_handles_bytes():
    out = to_jsonable(b"\x00\x01\x02")
    assert out == {"__type__": "bytes", "hex": "000102"}


def test_shared_secret_env_var_overrides_default(monkeypatch):
    monkeypatch.setenv("BATTLESPACE_AGENT_SECRET", "prod-key")
    assert shared_secret() == b"prod-key"
    monkeypatch.delenv("BATTLESPACE_AGENT_SECRET")
    assert shared_secret() == b"battlespace-dev-only-shared-secret-change-me"


def test_roundtrip_through_shared_secret(monkeypatch):
    monkeypatch.setenv("BATTLESPACE_AGENT_SECRET", "prod-key")
    blob = wrap({"contents": "X", "data": 9}, shared_secret())
    assert unwrap(blob, shared_secret(), STRICT_SCHEMA) == {"contents": "X", "data": 9}


def test_pack_unpack_roundtrip_dict():
    blob = pack({"a": 1, "b": [2, 3]}, SECRET)
    assert unpack(blob, SECRET) == {"a": 1, "b": [2, 3]}


def test_pack_unpack_roundtrip_list():
    # Non-dict values go through the __wave3_value__ wrapper transparently.
    blob = pack([1, 2, 3], SECRET)
    assert unpack(blob, SECRET) == [1, 2, 3]


def test_pack_unpack_roundtrip_string():
    blob = pack("hello world", SECRET)
    assert unpack(blob, SECRET) == "hello world"


def test_unpack_rejects_bad_signature():
    blob = bytearray(pack({"a": 1}, SECRET))
    blob[-1] ^= 0x01
    with pytest.raises(EnvelopeError):
        unpack(bytes(blob), SECRET)
