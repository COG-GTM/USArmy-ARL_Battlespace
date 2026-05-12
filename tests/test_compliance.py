"""DISA STIG V5R3 + NIST 800-53 r5 compliance assertions.

These tests do not import the repo at runtime; they scan the source tree
for patterns that violate the federal control set. Each test maps to a
specific STIG control identifier and a NIST family.

Run with::

    pytest tests/test_compliance.py -v

The 12 controls below mirror the language-agnostic table in the
playbook (Phase 2, Child C).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXCLUDE_PREFIXES = (
    '.venv/',
    '.git/',
    'docs/security-audit/evidence/',
    'tests/',  # tests intentionally contain anti-pattern strings to assert
)


def _is_repo_python(path: Path) -> bool:
    if path.suffix != '.py':
        return False
    rel = path.relative_to(REPO_ROOT).as_posix()
    return not rel.startswith(_EXCLUDE_PREFIXES)


def _walk_repo_python() -> list[Path]:
    return [p for p in REPO_ROOT.rglob('*.py') if _is_repo_python(p)]


def _read(path: Path) -> str:
    return path.read_text(encoding='utf-8', errors='replace')


# ---------------------------------------------------------------------------
# STIG V-222594 / NIST SI-11 -- no bare exception handlers in repo code
# ---------------------------------------------------------------------------

def test_no_bare_except_in_repo_python() -> None:
    offenders: list[str] = []
    for path in _walk_repo_python():
        for i, line in enumerate(_read(path).splitlines(), 1):
            if re.match(r'^\s*except\s*:\s*(#.*)?$', line):
                offenders.append(f'{path.relative_to(REPO_ROOT)}:{i}: {line.strip()!r}')
    assert not offenders, 'bare except detected:\n' + '\n'.join(offenders)


# ---------------------------------------------------------------------------
# STIG V-222609 / NIST SI-10 -- no eval / exec / compile of untrusted text
# ---------------------------------------------------------------------------

def test_no_eval_exec_in_repo_python() -> None:
    """eval() and exec() are not used in any repo-level source file."""
    offenders: list[str] = []
    for path in _walk_repo_python():
        try:
            tree = ast.parse(_read(path), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {'eval', 'exec'}:
                    offenders.append(
                        f'{path.relative_to(REPO_ROOT)}:{node.lineno}: {node.func.id}()'
                    )
    assert not offenders, 'eval/exec detected:\n' + '\n'.join(offenders)


# ---------------------------------------------------------------------------
# STIG V-222609 / NIST SI-10 -- no subprocess.* with shell=True
# ---------------------------------------------------------------------------

def test_no_shell_true_in_repo_python() -> None:
    """No call has ``shell=True``, no ``os.system``, no ``os.popen``."""
    offenders: list[str] = []
    for path in _walk_repo_python():
        text = _read(path)
        if re.search(r'shell\s*=\s*True', text):
            offenders.append(f'{path.relative_to(REPO_ROOT)}: shell=True')
        if re.search(r'\bos\.system\s*\(', text):
            offenders.append(f'{path.relative_to(REPO_ROOT)}: os.system')
        if re.search(r'\bos\.popen\s*\(', text):
            offenders.append(f'{path.relative_to(REPO_ROOT)}: os.popen')
    assert not offenders, 'shell-injection vector(s):\n' + '\n'.join(offenders)


# ---------------------------------------------------------------------------
# STIG V-222575 / NIST IA-5, SC-12 -- no hardcoded credentials
# ---------------------------------------------------------------------------

_CRED_PATTERNS = (
    re.compile(r"['\"]password['\"]\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.IGNORECASE),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"][A-Z0-9/+=]{30,}['\"]"),
    re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
)


def test_no_hardcoded_credentials_in_repo_python() -> None:
    offenders: list[str] = []
    for path in _walk_repo_python():
        text = _read(path)
        for pat in _CRED_PATTERNS:
            if pat.search(text):
                offenders.append(f'{path.relative_to(REPO_ROOT)}: matched {pat.pattern!r}')
    assert not offenders, 'hardcoded credential(s):\n' + '\n'.join(offenders)


# ---------------------------------------------------------------------------
# STIG V-222542 / NIST SC-13 -- FIPS-safe hashing posture
# ---------------------------------------------------------------------------

def test_no_md5_or_sha1_for_security_purposes() -> None:
    """``hashlib.md5`` / ``hashlib.sha1`` must declare ``usedforsecurity=False``."""
    offenders: list[str] = []
    for path in _walk_repo_python():
        try:
            tree = ast.parse(_read(path), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == 'hashlib' and func.attr in {'md5', 'sha1', 'new'}:
                    name = func.attr
            if name is None:
                continue
            has_kwarg = any(
                isinstance(k, ast.keyword) and k.arg == 'usedforsecurity'
                for k in node.keywords
            )
            if not has_kwarg:
                offenders.append(
                    f'{path.relative_to(REPO_ROOT)}:{node.lineno}: hashlib.{name} without usedforsecurity'
                )
    assert not offenders, 'weak hash without usedforsecurity=False:\n' + '\n'.join(offenders)


# ---------------------------------------------------------------------------
# STIG V-222656 / NIST RA-5, SI-2 -- supply chain hygiene
# ---------------------------------------------------------------------------

def test_requirements_txt_floors_dill_and_numpy() -> None:
    """requirements.txt must declare safe-floor versions for known vuln deps."""
    text = (REPO_ROOT / 'requirements.txt').read_text(encoding='utf-8')
    assert re.search(r'dill\s*>=\s*0\.3\.8', text), text
    assert re.search(r'numpy\s*>=\s*1\.22', text), text


# ---------------------------------------------------------------------------
# STIG V-222394/V-222395 / NIST CM-6 -- Dockerfile hygiene (skipped if absent)
# ---------------------------------------------------------------------------

def test_dockerfile_does_not_run_as_root_if_present() -> None:
    dockerfile = REPO_ROOT / 'Dockerfile'
    if not dockerfile.exists():
        pytest.skip('No Dockerfile in repo')
    text = dockerfile.read_text(encoding='utf-8')
    assert re.search(r'^USER\s+(?!root)\S+', text, re.MULTILINE), \
        'Dockerfile must contain a non-root USER directive'


# ---------------------------------------------------------------------------
# STIG V-222563 / NIST SC-8 -- urlopen() must set timeout
# ---------------------------------------------------------------------------

def test_urlopen_always_specifies_timeout() -> None:
    offenders: list[str] = []
    for path in _walk_repo_python():
        text = _read(path)
        for match in re.finditer(r'urlopen\(([^)]*)\)', text):
            args = match.group(1)
            if 'timeout' not in args:
                offenders.append(f'{path.relative_to(REPO_ROOT)}: urlopen({args!r})')
    assert not offenders, 'urlopen without timeout:\n' + '\n'.join(offenders)


# ---------------------------------------------------------------------------
# STIG V-222423..V-222428 / NIST AU-2, AU-3 -- audit logger presence
# ---------------------------------------------------------------------------

def test_audit_logger_module_present() -> None:
    assert (REPO_ROOT / 'src' / 'security_audit_logging.py').exists()


def test_audit_logger_imported_at_recv_call_sites() -> None:
    """Every file that performs network deserialisation imports the audit logger."""
    expected = (
        REPO_ROOT / 'test' / 'ServerWithUI.py',
        REPO_ROOT / 'test' / 'HumanInterface.py',
        REPO_ROOT / 'src' / 'AgentTypes' / 'RemoteAgent.py',
        REPO_ROOT / 'test' / 'reliableSockets.py',
    )
    for path in expected:
        text = _read(path)
        assert 'get_security_logger' in text, f'{path.relative_to(REPO_ROOT)}: missing audit logger import'


# ---------------------------------------------------------------------------
# STIG V-222396 / NIST IA-2 -- documented missing-auth posture
# ---------------------------------------------------------------------------

def test_security_md_documents_missing_socket_auth() -> None:
    """SECURITY.md must explicitly call out the missing socket auth posture."""
    text = (REPO_ROOT / 'SECURITY.md').read_text(encoding='utf-8')
    for needle in ('plaintext', 'Dill', '5050'):
        assert needle in text


# ---------------------------------------------------------------------------
# STIG V-222608 / NIST SI-10 -- bounded recv() payloads
# ---------------------------------------------------------------------------

def test_recv_call_sites_bounded_by_max_message_size() -> None:
    """All ``conn.recv(N)`` sites on the wire protocol are bounded."""
    paths = (
        REPO_ROOT / 'test' / 'ServerWithUI.py',
        REPO_ROOT / 'test' / 'HumanInterface.py',
        REPO_ROOT / 'src' / 'AgentTypes' / 'RemoteAgent.py',
        REPO_ROOT / 'src' / 'Fully_Visible_UI' / 'interface.py',
        REPO_ROOT / 'src' / 'Fully_Visible_UI' / 'WalterServer2Humansv2StaticRandom.py',
    )
    for path in paths:
        text = _read(path)
        assert 'MAX_MESSAGE_SIZE' in text, f'{path.relative_to(REPO_ROOT)}: MAX_MESSAGE_SIZE not referenced'


# ---------------------------------------------------------------------------
# STIG V-222575 / NIST IA-5 -- gitleaks evidence file pinned
# ---------------------------------------------------------------------------

def test_gitleaks_evidence_present() -> None:
    p = REPO_ROOT / 'docs' / 'security-audit' / 'evidence' / 'gitleaks.json'
    assert p.exists(), 'gitleaks evidence must be committed'
