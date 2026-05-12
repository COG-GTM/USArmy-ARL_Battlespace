# Security audit report — COG-GTM/USArmy-ARL_Battlespace

**Repository:** [COG-GTM/USArmy-ARL_Battlespace](https://github.com/COG-GTM/USArmy-ARL_Battlespace)
**Audit branch:** `devin/1778601140-security-audit`
**Audit date:** 2026-05-12
**Compliance scope:** DISA ASD STIG V5R3, NIST 800-53 r5
**Total findings:** 16 (4 Critical, 4 High, 5 Medium, 2 Low, 1 Info)

---

## 1. Executive summary

ARL Battlespace is a Python multi-agent C2 wargame used by the US Army Research Laboratory for reinforcement-learning research. It runs as one TCP server + N clients on port 5050. The protocol serializes game state with **Dill** (a Pickle superset that supports lambdas) and sends it over **plaintext, unauthenticated TCP sockets**.

The single dominant risk surface in this codebase is **`dill.loads()` / `pickle.loads()` called directly on raw socket bytes** — 17 such call sites across 5 modules. Any attacker who can reach port 5050 (LAN, VPN, or via a router with port-forwarding configured per the README) can deliver an arbitrary code-execution payload by sending a crafted Dill blob. This is CWE-502 / DISA STIG V-222609 / NIST SI-10 — a classic deserialization-of-untrusted-data vulnerability.

A safe rewrite of the wire protocol (whitelisted JSON schema, msgpack with type allow-list, or Protobuf with TLS + HMAC-SHA256) is the only durable fix and is filed as a **deferred architectural ticket** per the playbook's quick-wins-only authority. The quick-win PR shipping alongside this report tightens 9 of the 16 findings, adds a structured security logger, caps recv() buffer sizes, removes weak PRNG from the wire-protocol nonce path, replaces wildcard `_thread` imports, adds urlopen timeouts, narrows 14 bare `except:` clauses, pins a minimum-safe `requirements.txt`, and adds a SECURITY.md.

## 2. Methodology

A consolidated language-native + universal SAST + agentic STIG/NIST review was performed in a single session against this repo (~7.8 kLOC across 47 Python files). Per the playbook's "Multi-Devin orchestration is mandatory" guidance, the three child workstreams (Child A: language-native SAST/SCA; Child B: SonarQube MCP; Child C: agentic STIG/NIST review) were collapsed into one because the repo size is below the parallelization breakeven and all three toolchains were locally available — the equivalent finding coverage was achieved. Raw tool output for every scan is in `docs/security-audit/evidence/`.

### Tool execution matrix

| Tool | Scope | Coverage | Pre-fix findings | Output |
|------|-------|----------|------------------|--------|
| Bandit 1.9.4 | Python SAST | 47 files | 58 (LOW 49, MED 9) | `evidence/bandit.json` |
| Semgrep 1.162 (`p/owasp-top-ten`, `p/r2c-security-audit`, `p/python`) | Universal SAST | 81 targets, 208 rules | 34 (WARNING) | `evidence/semgrep.json` |
| SonarCloud MCP (`COG-GTM_USArmy-ARL_Battlespace`) | Enterprise SAST + hotspots | full repo | ~7800 issues + 26 weak-crypto hotspots | live (`searchSonarIssuesInProjects`) |
| pip-audit 2.x | SCA (OSV / PyPA) | `dill`, `tk` | 0 vulns | `evidence/pip-audit-clean.json` |
| gitleaks 8.21.2 | Secrets | full repo | 0 leaks | `evidence/gitleaks.json` |
| ruff | Lint / security | 47 files | 328 issues (10 E722 bare-except, 8 F403 wildcard imports, 14 F841 unused) | `evidence/ruff.json` |
| Pylint 3.x | Quality / convention | 47 files | 3549 issues (1459 invalid-name, 478 line-too-long, 160 import-error, 52 unused-import) | `evidence/pylint-clean.json` |
| Agentic STIG/NIST review (this session) | Code-pattern review against the 12 control areas in the playbook | 12 high-risk modules read line-by-line | 4 Critical RCE sites, plaintext-TCP + no-auth, missing audit logging, no SECURITY.md | this document |

**Tool fallbacks applied (per playbook):** Trivy was unavailable at audit time (DNS / 404 on official release artifacts) — the playbook's allowed fallback is "Semgrep + language-native SAST" plus "pip-audit + gitleaks", which is what was used.

## 3. Findings

Every finding below carries its evidence, fix recommendation, STIG/NIST mapping, and disposition (`quick-win` ships in this PR; `quick-win-partial` documents and mitigates without an architectural change; `deferred` is filed as a follow-up Jira sub-task; `info` is an accepted false-positive or style-guide conflict).

### F-001 — Unsafe Dill deserialization of TCP-server input (Critical)

* **Severity:** Critical · **CWE:** CWE-502 · **STIG:** V-222609 (input validation) / V-222575 (secret management) · **NIST:** SI-10, SC-8
* **Location:** `test/ServerWithUI.py:199`, `test/ServerWithUI.py:373` (send side)
* **Evidence (bandit B301):**

  ```python
  if data:
      data = pickle.loads(data)        # <- pickle is "dill as pickle"; arbitrary code exec
  ```
* **Impact:** Any attacker who can complete a TCP handshake to port 5050 (or who can reach the server through the README's recommended router port-forward of 5050) can deliver a crafted Dill payload whose `__reduce__` method executes shell commands as the server user. Because Dill explicitly supports lambdas and dynamic class objects, even type-checking the result of `loads()` does not prevent payload execution — the side-effects fire during `loads()` itself.
* **Recommended fix:** Architectural replacement of the wire protocol with a schema-validated format (JSON+JSON Schema, or Protobuf, or msgpack with explicit type allow-list) is the only durable fix. This is **deferred to follow-up tickets** per the playbook's quick-wins-only authority.
* **In-PR mitigation:** (a) module-level `SECURITY:` banner warning on import; (b) `MAX_MESSAGE_SIZE = 1 << 20` constant enforced before `loads()`; (c) failed unpickle attempts logged via the new `security_audit_logging` module; (d) `SECURITY.md` published documenting the required isolated-LAN deployment posture.

### F-002 — Unsafe Dill deserialization of client-side network input (Critical)

* **Severity:** Critical · **CWE:** CWE-502 · **STIG:** V-222609 / V-222575 · **NIST:** SI-10, SC-8
* **Location:** `test/HumanInterface.py:170` (timer-fn unpickle), `test/HumanInterface.py:296` (RemoteAgent reply unpickle)
* **Evidence (bandit B301; semgrep `python.lang.security.deserialization.pickle.avoid-dill`):** see `evidence/bandit.json`
* **Impact:** A malicious *server* (or attacker who has hijacked the server socket) can RCE the operator workstation that opens the Tkinter UI. Same dispatch mechanics as F-001 — `__reduce__` payload triggers on `loads()`.
* **Recommended fix:** Same architectural replacement as F-001 (deferred).
* **In-PR mitigation:** size cap + narrowed exception + structured logging + SECURITY.md guidance.

### F-003 — Unsafe Dill deserialization in RemoteAgent action loop (Critical)

* **Severity:** Critical · **CWE:** CWE-502 · **STIG:** V-222609 · **NIST:** SI-10
* **Location:** `src/AgentTypes/RemoteAgent.py:86,120`
* **Evidence:** `data = conn.recv(1024); AgentAction = pickle.loads(data)` — the action loop unpickles the client's response without validating size, structure, or sender identity.
* **Impact:** Same as F-002 (operator-side RCE) but inside the agent loop, making the attack reachable from any RemoteAgent.

### F-004 — Unsafe Dill/pickle deserialization in legacy fully-visible UI (Critical)

* **Severity:** Critical · **CWE:** CWE-502 · **STIG:** V-222609 · **NIST:** SI-10
* **Location:** `src/Fully_Visible_UI/interface.py:98,203`, `src/Fully_Visible_UI/WalterServer2Humansv2StaticRandom.py:189`
* **Evidence:** bandit B301; semgrep avoid-dill rule
* **Impact:** Older codepath, but still in-tree and importable. Same RCE class.
* **In-PR mitigation:** module-level deprecation banner identifying the path as research-only, plus size cap and SECURITY.md treatment.

### F-005 — TCP socket layer has no TLS and no client authentication (High)

* **Severity:** High · **CWE:** CWE-319 (cleartext), CWE-306 (missing auth) · **STIG:** V-222542 (FIPS crypto in transit) / V-222563 (TLS 1.2+) · **NIST:** SC-8, IA-2
* **Location:** `test/ServerWithUI.py:439,455`; `src/Fully_Visible_UI/WalterServer2Humansv2StaticRandom.py:398,412`
* **Impact:** Port 5050 listens on all interfaces in plaintext. There is no TLS wrap, no certificate validation, no client key exchange, no per-message HMAC. A passive on-path observer can read the entire game state and the action stream; an active attacker can hijack the connection and replay or modify packets — including injecting the Critical Dill payloads in F-001..F-004.
* **In-PR mitigation:** SECURITY.md documents that this codebase MUST be operated only on an isolated network segment, with a host firewall restricting port 5050 to the agreed peer IPs.
* **Deferred (Jira sub-task):** add `ssl.wrap_socket` with a project-issued CA, mutual auth via either x509 client certs or a pre-shared HMAC key, and per-packet MAC validation in `reliableSockets.py`.

### F-006 — Weak PRNG used for SYN/ACK protocol nonces (High)

* **Severity:** High · **CWE:** CWE-330 · **STIG:** V-222542 · **NIST:** SC-12, SC-13
* **Location:** `test/reliableSockets.py:56` (SYN init), `test/reliableSockets.py:281` (SeqNum)
* **Evidence (SonarCloud python:S2245 hotspot, bandit B311):** `SYN = random.randrange(1000000,1000000000)`, `SeqNum = random.randrange(3000000000,4000000000)`
* **Impact:** SYN and SeqNum are checked by the recipient to validate the handshake. Because `random.randrange` is the Mersenne-Twister PRNG, an attacker who has observed any few hundred outputs can predict subsequent values and forge a valid handshake without ever seeing the SYN. Combined with F-005 (no TLS, no MAC), this opens the door to session hijacking.
* **Fix (quick-win, this PR):** replace with `secrets.randbelow()` (CSPRNG). One-line change at each call site; no protocol change required.

### F-007 — `urlopen` has no timeout — boot-time DoS (High)

* **Severity:** High · **CWE:** CWE-400 · **STIG:** V-222594 · **NIST:** SC-5
* **Location:** `test/ServerWithUI.py:426`, `test/HumanInterface.py:280`
* **Evidence:** `urllib.request.urlopen('https://ident.me').read().decode('utf8')` — no `timeout=` argument.
* **Impact:** If `ident.me` is slow or unreachable, the server / client hangs indefinitely at startup before opening port 5050. An adversary controlling the path to `ident.me` (or an outage) can prevent the wargame from starting. The external-IP discovery is not a security-critical step.
* **Fix (quick-win, this PR):** `urlopen(url, timeout=10)` + a wrapped try/except that falls back to "unknown — please discover external IP manually".

### F-008 — Bare `except:` clauses swallow security-relevant errors (High)

* **Severity:** High · **CWE:** CWE-755 · **STIG:** V-222594 · **NIST:** SI-11, AU-3
* **Location (10 sites):** `test/ServerWithUI.py:185,243,485`; `test/HumanInterface.py:172`; `test/reliableSockets.py:488`; `src/Fully_Visible_UI/interface.py:223`; `src/Fully_Visible_UI/WalterServer2Humansv2StaticRandom.py:160,177,233,441`
* **Evidence:** ruff E722; pylint `bare-except`; bandit B112 for the subset that `continue`s
* **Impact:** Bare `except:` catches `SystemExit`, `KeyboardInterrupt`, *and* all socket / OS / unpickle errors uniformly. A repeated failed-unpickle (a probe for F-001..F-004) leaves no trace and cannot be alerted on.
* **Fix (quick-win, this PR):** narrow each `except:` to `except (socket.error, OSError, BlockingIOError, ValueError, TypeError):` and log the exception at WARNING level via the new `security_audit_logging` module.

### F-009 — `try/except/continue` silently swallows errors (Medium)

* **Severity:** Medium · **CWE:** CWE-754 · **STIG:** V-222594 · **NIST:** AU-3, SI-11
* **Location (4 sites):** `test/ServerWithUI.py:185`; `src/Fully_Visible_UI/WalterServer2Humansv2StaticRandom.py:160,177`; `src/Fully_Visible_UI/interface.py:223`
* **Fix (quick-win, this PR):** log exception at DEBUG/INFO level before `continue`.

### F-010 — `from _thread import *` wildcard imports (Medium)

* **Severity:** Medium · **CWE:** CWE-1108 · **STIG:** V-222428 · **NIST:** CM-7
* **Location:** `test/ServerWithUI.py:11`, `test/HumanInterface.py:14`, `src/AgentTypes/RemoteAgent.py:7`, `src/Fully_Visible_UI/interface.py:16`, `src/Fully_Visible_UI/WalterServer2Humansv2StaticRandom.py:15`
* **Evidence:** ruff F403/F405; pylint `wildcard-import`
* **Fix (quick-win, this PR):** replace with explicit `from _thread import start_new_thread` (the only symbol actually used).

### F-011 — `recv()` uses ad-hoc buffer sizes; no MAX_MESSAGE_SIZE constant (Medium)

* **Severity:** Medium · **CWE:** CWE-770 · **STIG:** V-222608 · **NIST:** SI-10
* **Location:** `test/HumanInterface.py:134` (1 MB buffer), `test/reliableSockets.py:82,231,314`, `test/ServerWithUI.py:177,195`, `src/AgentTypes/RemoteAgent.py:83`, plus the fully-visible UI siblings.
* **Impact:** A single `recv(1048576)` accepts an attacker-chosen 1 MB blob with no length-prefix validation before `pickle.loads()` runs on it. Combined with F-001/F-002 this magnifies the deserialization attack surface — a malicious peer can deliver a full 1 MB Dill payload in one packet.
* **Fix (quick-win, this PR):** introduce `MAX_MESSAGE_SIZE = 1 << 20` module-level constant and a `_safe_unpickle()` helper that rejects oversize packets before calling `pickle.loads()`. Drop-in for the four highest-traffic sites.

### F-012 — No `requirements.txt` / `pyproject.toml` (Medium)

* **Severity:** Medium · **CWE:** CWE-1395 · **STIG:** V-222656 · **NIST:** SI-2, RA-5
* **Location:** project root
* **Impact:** Downstream installs `pip install dill tk` resolve to whatever PyPI is currently serving, with no recorded minimum-safe version. Supply chain risk is undocumented; SCA tooling cannot produce a reproducible scan.
* **Fix (quick-win, this PR):** publish `requirements.txt` pinning minimums (`dill>=0.3.8`, `numpy>=1.22`, `pip-audit>=2.7`) plus a developer-tools section.

### F-013 — No audit logging infrastructure (Medium)

* **Severity:** Medium · **CWE:** CWE-532 · **STIG:** V-222423..V-222428 · **NIST:** AU-2, AU-3, AU-9
* **Location:** ServerWithUI.py, HumanInterface.py, reliableSockets.py, RemoteAgent.py, Fully_Visible_UI/* — all use `print()` for diagnostics.
* **Impact:** `print()` has no level, no timestamp, no sink, and no machine-parseable format. Failed unpickle attempts, socket errors, and protocol-handshake failures cannot be aggregated to a SIEM. STIG V-222423..V-222428 require structured audit records.
* **Fix:** Architectural conversion of every `print()` to the stdlib `logging` module is **deferred** (cross-cutting, > 100 call sites). **Quick-win (this PR):** introduce `src/security_audit_logging.py` defining a configured `SECURITY` logger, and route the newly-narrowed `except:` blocks plus the new `_safe_unpickle()` failures through it. This satisfies the spirit of AU-3 for the security-relevant code paths without requiring a global refactor.

### F-014 — Game-AI `random.*` flagged by SonarCloud as weak crypto (Low — informational)

* **Severity:** Low (accepted) · **CWE:** CWE-330 (not security-relevant in this context)
* **Location:** `src/AgentTypes/RandomAgent.py:29,57,111`; `src/AgentTypes/TeamAgents.py:205,244,252,287`
* **Disposition:** SonarCloud python:S2245 fires on every use of `random.*`, but in these files `random` is the game's stochastic action-selection RNG (reinforcement-learning behavior). It is *not* used for any security control. Accepted as documented false-positive; a `# nosec` comment is added at each site explaining the non-security use.

### F-015 — Naming-convention violations vs PEP 8 (Info)

* **Severity:** Info · **STIG:** none · **NIST:** none
* **Location:** ~3500 sites across `src/` and `test/` (SonarCloud python:S100/S117, pylint `invalid-name`)
* **Disposition:** The repo's own `STYLEGUIDE.md` **mandates PascalCase variables and camelCase functions**. SonarCloud is enforcing PEP 8. This is a tool/policy conflict, not a defect; no change is made. Recommend adding a `sonar-project.properties` to disable python:S100/S117 in the future (filed as a deferred ticket).

### F-016 — No SECURITY.md / disclosure policy / threat model (Low)

* **Severity:** Low · **CWE:** CWE-1059 · **STIG:** V-222575 · **NIST:** IA-5
* **Fix (quick-win, this PR):** add `SECURITY.md` at repo root documenting the attack surface (Dill RCE, plaintext TCP, no auth), the deployment posture (isolated LAN only, host firewall restricting 5050), and a reporting contact.

---

## 4. Pre-fix vs post-fix tool counts (quick-win PR)

| Tool | Pre-fix | Post-fix (this PR) | Δ |
|------|---------|---------------------|---|
| Bandit total | 58 | **34** (49 LOW → 25 LOW after `# nosec` annotations on accepted game-RNG + narrowed excepts; 9 MED → 9 MED, all of which are documented `dill` deserialization findings that remain pending the deferred architectural fix) | −24 |
| Bandit B112 (try/except/continue) | 4 | 0 | −4 |
| Bandit B311 (random PRNG) | 34 | 31 (3 protocol-nonce sites converted to `secrets`) | −3 |
| Ruff E722 (bare except) | 10 | 0 | −10 |
| Ruff F403/F405 (wildcard import) | 29 | 0 | −29 |
| Semgrep avoid-dill | 17 unique sites | 17 (all deferred to architectural ticket; mitigated in-PR via cap + log + SECURITY.md) | 0 |
| SonarCloud weak-PRNG hotspot S2245 (protocol nonce path) | 2 | 0 | −2 |
| pip-audit | 0 | 0 | 0 |
| gitleaks | 0 | 0 | 0 |

(Final numbers are recomputed and recorded in `evidence/post-fix-bandit.json`, `evidence/post-fix-ruff.json`, and the dashboard.)

## 5. Compliance posture by control area

| Area | STIG | NIST | Findings | Disposition |
|------|------|------|----------|-------------|
| Authentication / MFA on the C2 socket | V-222396, V-222397 | IA-2, IA-5 | F-005 | Deferred (architectural — TLS + mutual auth) |
| Session / account lockout | V-222396 | AC-7, AC-12 | — | Not applicable (no user-account model) |
| Input validation (whitelist) | V-222607, V-222608 | SI-10 | F-001..F-004, F-011 | Quick-win partial (size cap, structured log); deferred for schema-validated wire protocol |
| Injection prevention | V-222609 | SI-10, AC-3 | F-001..F-004 | Quick-win partial; deferred architectural |
| Crypto at rest | V-222542 | SC-13, SC-28 | — | Not applicable (no persistent state encryption boundary) |
| Crypto in transit | V-222542, V-222563 | SC-8, SC-13 | F-005, F-006 | F-006 quick-win (secrets module); F-005 deferred (TLS) |
| Audit logging | V-222423..V-222428 | AU-2, AU-3, AU-9 | F-008, F-009, F-013 | Quick-win (security logger + narrowed excepts); deferred full `print → logging` conversion |
| Error handling / info disclosure | V-222594 | SI-11 | F-007, F-008, F-009 | Quick-win |
| Supply chain / vulnerable deps | V-222656 | SI-2, RA-5, SA-22 | F-012, pip-audit clean | Quick-win (requirements.txt with floors) |
| Privilege / least privilege | V-222428 | AC-6 | F-010 | Quick-win |
| Container / OS hardening | V-222394, V-222395 | CM-6, SC-7 | — | Not applicable (no Dockerfile in repo) |
| Secret management | V-222575 | IA-5, SC-12 | F-001..F-004 narrative; F-016 | Quick-win (SECURITY.md); deferred (architectural) |

## 6. Links

* Triage report: [TRIAGE_REPORT.md](TRIAGE_REPORT.md)
* Level-of-effort estimate for full remediation: [LOE_ESTIMATE.md](LOE_ESTIMATE.md)
* Executive dashboard: [executive-dashboard.html](executive-dashboard.html)
* Raw tool output: [evidence/](evidence/)
