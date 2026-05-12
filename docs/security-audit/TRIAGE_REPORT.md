# Triage report — COG-GTM/USArmy-ARL_Battlespace

**Audit branch:** `devin/1778601140-security-audit`
**Audit date:** 2026-05-12
**Authority:** ship quick-wins in this PR; defer architectural change to follow-up Jira tickets with LOE.

## Priority groups

### P1 — Immediate (this PR + immediate follow-up architectural ticket)

| ID | Severity | Finding | Quick-win in this PR | Deferred architectural work |
|----|----------|---------|----------------------|-----------------------------|
| F-001 | Critical | Server-side Dill RCE on socket input | size cap + structured log + module-level warning + SECURITY.md | Replace Dill with schema-validated wire protocol (UF-xxx) |
| F-002 | Critical | Client-side Dill RCE on socket input | size cap + structured log + module-level warning | Replace Dill with schema-validated wire protocol (UF-xxx) |
| F-003 | Critical | RemoteAgent Dill RCE | size cap + structured log + narrowed except | Replace Dill (UF-xxx) |
| F-004 | Critical | Legacy fully-visible UI Dill RCE | size cap + deprecation banner | Either drop the legacy path or migrate it onto the new wire protocol (UF-xxx) |

### P2 — Short-term (this PR plus 1 follow-up sprint)

| ID | Severity | Finding | In-PR | Deferred |
|----|----------|---------|--------|----------|
| F-005 | High | Plaintext TCP / no auth | SECURITY.md isolated-LAN guidance | Add TLS 1.2+ with mutual auth + per-packet HMAC (UF-xxx) |
| F-006 | High | Weak PRNG on protocol nonces | Replace `random.randrange` → `secrets.randbelow` at 2 sites in `reliableSockets.py` | — |
| F-007 | High | Missing `urlopen` timeout | `timeout=10` + try/except/fallback at 2 sites | — |
| F-008 | High | Bare `except:` clauses | Narrow 10 sites to specific exception types + log | — |

### P3 — Medium-term

| ID | Severity | Finding | In-PR | Deferred |
|----|----------|---------|--------|----------|
| F-009 | Medium | `try/except/continue` swallow | Log before continue (4 sites) | — |
| F-010 | Medium | Wildcard `_thread` imports | Replace with explicit imports (5 files) | — |
| F-011 | Medium | recv() with no size cap | `MAX_MESSAGE_SIZE` constant + `_safe_unpickle()` helper | — |
| F-012 | Medium | No requirements.txt | Publish requirements.txt with floors | Move to pyproject.toml + uv lockfile (UF-xxx) |
| F-013 | Medium | No structured audit logging | Add `security_audit_logging.py` for security-relevant paths | Full `print → logging` conversion (UF-xxx) |

### P4 — Accept / Defer / Style

| ID | Severity | Finding | Disposition |
|----|----------|---------|-------------|
| F-014 | Low | Game-AI `random.*` flagged by SonarCloud weak-PRNG hotspot | Accepted as not-security; annotate with `# nosec` and a comment explaining game-RNG context |
| F-015 | Info | SonarCloud naming violations | Accepted — conflicts with repo's STYLEGUIDE.md (PascalCase/camelCase). Suppress in `sonar-project.properties` (UF-xxx). |
| F-016 | Low | No SECURITY.md | Quick-win — published in this PR |

## Effort breakdown (LOC delta)

| ID | LOC added | LOC removed | LOC modified | ACU est. |
|----|-----------|-------------|---------------|----------|
| F-001..F-004 (combined quick-win mitigation) | 60 | 0 | 0 | 0.5 |
| F-005 (in-PR mitigation only) | 0 (text-only in SECURITY.md) | 0 | 0 | 0.05 |
| F-006 | 6 | 0 | 2 | 0.1 |
| F-007 | 16 | 0 | 4 | 0.1 |
| F-008 | 0 | 0 | 30 (narrowed except + log) | 0.4 |
| F-009 | 8 | 0 | 4 | 0.1 |
| F-010 | 0 | 5 | 5 (explicit imports) | 0.1 |
| F-011 | 30 | 0 | 12 | 0.3 |
| F-012 | 25 (requirements.txt) | 0 | 0 | 0.1 |
| F-013 | 55 (security_audit_logging.py) | 0 | 0 | 0.3 |
| F-014 | 0 | 0 | 7 (comment annotations) | 0.05 |
| F-016 | 70 (SECURITY.md) | 0 | 0 | 0.1 |
| Compliance test suite (regression + STIG/NIST assertions) | 180 (two new test files) | 0 | 0 | 0.6 |
| Executive dashboard | 350 (HTML + assets) | 0 | 0 | 0.6 |
| **TOTAL in this PR** | **~800** | **~5** | **~64** | **~3.3** |

(See `LOE_ESTIMATE.md` for the deferred-ticket roll-up.)

## Sub-task slicing (ship in this PR)

* **A. Wire safety hardening** — F-006, F-007, F-008, F-009, F-010, F-011 (one commit)
* **B. Documentation & supply chain** — F-012, F-016 (one commit)
* **C. Audit logging primitives** — F-013 in-PR portion (one commit)
* **D. Compliance test suite** — tests/test_security_audit.py + tests/test_compliance.py (one commit)
* **E. Executive dashboard + reports** — docs/security-audit/* (one commit)

Reviewer load is balanced across the five commits; each commit is < 200 LOC and individually revertable.
