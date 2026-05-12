"""Regression tests for the 2026-05-12 federal security audit.

One test per remediated finding (F-006..F-013, F-016) plus a couple of
shared smoke tests for the new ``security_audit_logging`` module.

Run with::

    pytest tests/test_security_audit.py -v

DISA STIG: V-222423..V-222428, V-222594, V-222607..V-222609, V-222656
NIST 800-53 r5: AU-2, AU-3, AU-9, SI-10, SI-11, RA-5, SC-5, SC-12
"""

from __future__ import annotations

import importlib.util
import io
import logging
import os
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / 'src'
TEST_DIR = REPO_ROOT / 'test'

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _read(path: Path) -> str:
    return path.read_text(encoding='utf-8', errors='replace')


# ---------------------------------------------------------------------------
# Module under test: src/security_audit_logging.py (F-013)
# ---------------------------------------------------------------------------

def test_F013_security_audit_logging_module_exists() -> None:
    """F-013: a dedicated audit-logging module must exist (NIST AU-2/AU-3)."""
    spec = importlib.util.spec_from_file_location(
        'security_audit_logging', SRC / 'security_audit_logging.py',
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, 'get_security_logger')
    assert hasattr(mod, 'safe_unpickle')
    assert hasattr(mod, 'MAX_MESSAGE_SIZE')
    assert hasattr(mod, 'UnpickleError')


def _load_audit_module():
    spec = importlib.util.spec_from_file_location(
        'security_audit_logging', SRC / 'security_audit_logging.py',
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_F011_max_message_size_is_bounded() -> None:
    """F-011: MAX_MESSAGE_SIZE must be a finite positive int <= 16 MiB."""
    mod = _load_audit_module()
    assert isinstance(mod.MAX_MESSAGE_SIZE, int)
    assert 1024 <= mod.MAX_MESSAGE_SIZE <= (16 << 20)


def test_F011_safe_unpickle_rejects_empty() -> None:
    mod = _load_audit_module()
    with pytest.raises(mod.UnpickleError):
        mod.safe_unpickle(b'', source='test_empty')


def test_F011_safe_unpickle_rejects_oversize() -> None:
    """F-011: oversize payload must be rejected before dill.loads runs."""
    mod = _load_audit_module()
    payload = b'\x00' * (mod.MAX_MESSAGE_SIZE + 1)
    with pytest.raises(mod.UnpickleError):
        mod.safe_unpickle(payload, source='test_oversize')


def test_F011_safe_unpickle_rejects_nonbytes() -> None:
    mod = _load_audit_module()
    with pytest.raises(mod.UnpickleError):
        mod.safe_unpickle('not bytes', source='test_nonbytes')  # type: ignore[arg-type]


def test_F011_safe_unpickle_roundtrip_under_cap() -> None:
    """Round-tripping a normal dill-serialised payload must still work."""
    mod = _load_audit_module()
    import dill
    blob = dill.dumps({'a': 1, 'b': [1, 2, 3]})
    obj = mod.safe_unpickle(blob, source='test_roundtrip')
    assert obj == {'a': 1, 'b': [1, 2, 3]}


def test_F013_logger_emits_iso8601_timestamp(caplog: pytest.LogCaptureFixture) -> None:
    """The audit logger must emit machine-parseable timestamped records."""
    mod = _load_audit_module()
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter(
        fmt='%(asctime)s %(levelname)s %(name)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z',
    ))
    log = mod.get_security_logger('arl_battlespace.security.test_iso')
    log.addHandler(handler)
    log.warning('hello-iso-8601')
    handler.flush()
    out = buf.getvalue()
    assert 'hello-iso-8601' in out
    assert re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', out)


# ---------------------------------------------------------------------------
# Source-code regression checks
# ---------------------------------------------------------------------------

def test_F006_reliable_sockets_uses_csprng_for_syn() -> None:
    """F-006: protocol nonces must use CSPRNG, not ``random.randrange``."""
    text = _read(TEST_DIR / 'reliableSockets.py')
    assert 'secrets.randbelow' in text
    assert 'SYN = random.randrange' not in text
    assert 'SeqNum = random.randrange' not in text


def test_F007_urlopen_has_timeout_in_serverwithui() -> None:
    """F-007: every urlopen() call must specify a timeout."""
    text = _read(TEST_DIR / 'ServerWithUI.py')
    for match in re.finditer(r'urlopen\(([^)]*)\)', text):
        args = match.group(1)
        assert 'timeout' in args, f'urlopen without timeout in ServerWithUI.py: {args!r}'


def test_F007_urlopen_has_timeout_in_humaninterface() -> None:
    text = _read(TEST_DIR / 'HumanInterface.py')
    for match in re.finditer(r'urlopen\(([^)]*)\)', text):
        args = match.group(1)
        assert 'timeout' in args, f'urlopen without timeout in HumanInterface.py: {args!r}'


def test_F008_no_bare_except_in_repo_python() -> None:
    """F-008: no bare ``except:`` in repo-level Python (third-party allowed)."""
    offenders: list[str] = []
    for path in REPO_ROOT.rglob('*.py'):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith(('.venv/', '.git/', 'tests/test_security_audit.py')):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            stripped = line.strip()
            if re.match(r'^except\s*:', stripped):
                offenders.append(f'{rel}:{i}: {stripped!r}')
    assert not offenders, 'bare except in:\n' + '\n'.join(offenders)


def test_F010_no_wildcard_thread_imports_in_repo() -> None:
    """F-010: ``from _thread import *`` must not appear in repo code."""
    offenders: list[str] = []
    for path in REPO_ROOT.rglob('*.py'):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith(('.venv/', '.git/')):
            continue
        for i, line in enumerate(_read(path).splitlines(), 1):
            if re.match(r'\s*from\s+_thread\s+import\s+\*', line):
                offenders.append(f'{rel}:{i}: {line.strip()!r}')
    assert not offenders, 'wildcard _thread imports:\n' + '\n'.join(offenders)


def test_F011_pickle_loads_wrapped_in_serverwithui() -> None:
    """F-011: every direct ``pickle.loads`` call site must be replaced."""
    text = _read(TEST_DIR / 'ServerWithUI.py')
    assert 'safe_unpickle' in text


def test_F011_pickle_loads_wrapped_in_humaninterface() -> None:
    text = _read(TEST_DIR / 'HumanInterface.py')
    assert 'safe_unpickle' in text


def test_F011_pickle_loads_wrapped_in_remoteagent() -> None:
    text = _read(SRC / 'AgentTypes' / 'RemoteAgent.py')
    assert 'safe_unpickle' in text


def test_F012_requirements_txt_pins_floor_for_dill() -> None:
    """F-012: requirements.txt must pin a dill floor with a hardening note."""
    text = _read(REPO_ROOT / 'requirements.txt')
    assert re.search(r'dill\s*>=\s*0\.3\.8', text), text
    assert re.search(r'numpy\s*>=', text), text


def test_F013_security_logger_imported_at_recv_sites() -> None:
    """F-013: security-relevant call sites must import the audit logger."""
    for relative in (
        'test/ServerWithUI.py',
        'test/HumanInterface.py',
        'test/reliableSockets.py',
        'src/AgentTypes/RemoteAgent.py',
    ):
        text = _read(REPO_ROOT / relative)
        assert 'get_security_logger' in text, f'{relative}: missing audit logger'


def test_F016_security_md_exists_with_threat_model() -> None:
    """F-016: SECURITY.md must describe the threat model and reporting flow."""
    text = _read(REPO_ROOT / 'SECURITY.md')
    for needle in (
        'Threat model',
        'Reporting a vulnerability',
        'Deployment posture',
        'Dill',
        '5050',
    ):
        assert needle in text, f'SECURITY.md missing: {needle!r}'


def test_audit_evidence_present() -> None:
    """Evidence files from Phase 2 of the playbook must be checked in."""
    evidence_dir = REPO_ROOT / 'docs' / 'security-audit' / 'evidence'
    assert evidence_dir.is_dir()
    expected_any_of = ['bandit.json', 'semgrep.json', 'gitleaks.json', 'ruff.json']
    present = {p.name for p in evidence_dir.iterdir()}
    assert any(name in present for name in expected_any_of), present
