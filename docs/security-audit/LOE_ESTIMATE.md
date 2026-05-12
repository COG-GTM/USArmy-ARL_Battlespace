# Level-of-effort estimate — full remediation of USArmy-ARL_Battlespace

**Audit date:** 2026-05-12
**Quick-win PR:** [#9](https://github.com/COG-GTM/USArmy-ARL_Battlespace/pull/9)
**Tracking Epic:** [UF-249](https://cog-gtm.atlassian.net/browse/UF-249)
**Compliance scope:** DISA STIG V5R3 + NIST 800-53 r5

This document estimates LOC delta and ACU burn to close **every remaining finding** after the quick-win PR merges. PR #9 already ships 10 of 17. The remaining 5 deferred items (F-001..F-005) are all architectural and best landed as a small slice of focused PRs rather than one mega-PR.

## Summary

| | LOC delta | ACU est. | Wall-clock |
|---|---|---|---|
| PR-A — Safe wire protocol (F-001..F-004) | +650 / −180 | 22 ACU | 1 working week |
| PR-B — TLS 1.2+ + mutual auth on port 5050 (F-005) | +180 / −40 | 6 ACU | 2 working days |
| PR-C — Audit-logger port of legacy print() sites (housekeeping, F-013 follow-up) | +60 / −60 | 2 ACU | 0.5 day |
| **Total** | **+890 / −280** | **30 ACU** | **≈8 working days** |

ACU estimates are based on the parent-session methodology used on `COG-GTM/USArmy-Dshell` PR #21 (similar repo size, similar protocol-redesign LOC band). Cap is conservative; a small fraction (~5%) of buffer is included for Devin Review iteration loops.

---

## PR-A — Safe wire protocol replacement (F-001 → F-004)

**Goal:** retire `pickle.loads` / `dill.loads` on the wire. Replace with a versioned, whitelisted message schema with explicit per-type dispatch.

**Scope (4 modules):**
1. `test/ServerWithUI.py` — server accept loop, recv() pipeline
2. `test/HumanInterface.py` — client recv() and event-loop
3. `src/AgentTypes/RemoteAgent.py` — agent action loop
4. `src/Fully_Visible_UI/interface.py` + `WalterServer2Humansv2StaticRandom.py` — legacy fully-visible UI

**Design:**
- Add `src/protocol/messages.py` defining a small pydantic v2 model hierarchy: `Hello`, `JoinTeam`, `AgentAction`, `StateSnapshot`, `Goodbye`. Each carries an integer `protocol_version` and a discriminated `kind`.
- Add `src/protocol/codec.py`: `encode(msg) -> bytes` (length-prefixed JSON), `decode(buf) -> Message` with strict schema validation. Reject anything that doesn't validate before any Python object construction.
- Replace `safe_unpickle(...)` at each recv() site with `codec.decode(...)` and a per-type dispatch table — no more "deserialise then introspect."
- Keep `safe_unpickle` available *only* for explicit `--legacy-pickle` flag for backwards-compat with older agent binaries during transition; default OFF.

**Test plan:**
- Property tests over the schema (Hypothesis): every accepted bytes string round-trips.
- Negative tests: malformed JSON, extra keys, type mismatch, oversized payload all rejected with audit-log line and no exception leakage.
- Integration test: existing pytest suite continues to pass.

**LOC:** +650 added / −180 removed (replacing pickle.loads call sites and the helper plumbing they require).
**ACU:** 22 (roughly: 4 for schema design, 8 for codec + dispatch, 6 for porting 4 modules, 4 for test suite + Devin Review iteration).

## PR-B — TLS + mutual auth on port 5050 (F-005)

**Goal:** terminate the practice of accepting plaintext, unauthenticated connections on the C2 port.

**Scope:**
- Wrap server-side accept loop with `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`, load cert/key from configurable paths.
- Wrap client-side connect with `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`, require server cert verification.
- Add mutual auth — either x509 client certs (`SSLContext.verify_mode = ssl.CERT_REQUIRED`) or a configurable PSK that's verified inside the first `Hello` message.
- Update `SECURITY.md` to document the new deployment story (cert provisioning, rotation).

**LOC:** +180 added / −40 removed.
**ACU:** 6 (design 1, server wrap 2, client wrap 2, test/docs 1).

## PR-C — Housekeeping: port residual `print()` statements to audit logger (F-013 follow-up)

**Goal:** make all security-relevant code paths use `_audit_log` so that audit posture matches across the codebase. This is cosmetic — no behavioural change.

**Scope:** ~80 `print()` lines across game-engine and agent modules. Mechanical port to `_audit_log.debug(...)` / `_audit_log.info(...)`.

**LOC:** +60 / −60.
**ACU:** 2.

## PR slicing rationale

- **PR-A and PR-B are independent.** PR-B can technically land first (it's smaller, lower-risk), but the recommendation is **PR-A first** because TLS without a safe message schema does not defeat the RCE: an attacker on the LAN with stolen creds can still exploit Dill. PR-A is the higher-impact ticket.
- **PR-C is intentionally last and trivially reviewable** — drop it if the team prefers to leave `print()` in place.

## What this LOE does NOT include

- Migrating to a different transport (gRPC, ZeroMQ): not recommended for a research repo of this size.
- Adding plugin allow-lists for `RemoteAgent`: separate research task, not a STIG/NIST gap.
- Container hardening: no Dockerfile in the repo today; if one is added later, run STIG V-222394/V-222395 controls and re-audit.

## Handoff

PR #9 is open and CI is running. The PR contains the audit report, the triage report, the evidence folder, the compliance suite, and the 10 quick-win remediations. The 5 deferred items (UF-250..UF-254) are tracked under Epic UF-249. This LOE estimate is the recommended sequencing for closing them out.
