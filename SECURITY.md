# Security policy — USArmy-ARL_Battlespace

> **Audience:** operators deploying this codebase for reinforcement-learning research, and security reviewers performing DISA STIG / NIST 800-53 r5 assessment.
> **Status:** living document. Last updated 2026-05-12 (see `docs/security-audit/SECURITY_AUDIT_REPORT.md`).

## 1. Threat model

This codebase is a multi-agent C2 wargame. The reference deployment is one TCP server (`test/ServerWithUI.py`) listening on port `5050` and N clients (`test/HumanInterface.py`, `src/AgentTypes/RemoteAgent.py`) connecting from peer workstations.

The wire protocol is **Dill** (a Pickle superset that supports lambdas) serialized over **plaintext, unauthenticated TCP**. The protocol layer (`test/reliableSockets.py`) adds packet-level reassembly but does **not** add authentication, integrity, or confidentiality.

The dominant security risk surface is:

| Risk | Where | Mitigation in this PR | Architectural fix |
|------|-------|------------------------|--------------------|
| **Arbitrary code execution via crafted Dill payload on `recv()`** (CWE-502, STIG V-222609, NIST SI-10) | every `pickle.loads(data)` site — `ServerWithUI:199`, `HumanInterface:170,296`, `RemoteAgent:86,120`, `Fully_Visible_UI/*` | size-cap via `MAX_MESSAGE_SIZE`, structured audit logging of every attempt, narrowed exception handlers | **Deferred.** Replace Dill with JSON-Schema-validated or Protobuf wire protocol (see deferred Jira sub-tasks under the audit Epic) |
| **Passive eavesdropping & active hijack of port 5050** (CWE-319/306, STIG V-222542/V-222563, NIST SC-8/IA-2) | `socket.socket(AF_INET, SOCK_STREAM)` in `ServerWithUI:433` and the matching client `connect` | run on an isolated network segment only (see §3) | **Deferred.** `ssl.wrap_socket` with mutual auth + per-packet HMAC |
| **Forgeable protocol nonces** (CWE-330, NIST SC-12) | `random.randrange()` for SYN/SeqNum in `reliableSockets:56,281` | replaced with `secrets.randbelow()` in this PR | — |
| **Boot-time DoS via slow `urlopen`** (CWE-400, NIST SC-5) | `urllib.request.urlopen('https://ident.me')` in `ServerWithUI:426` and `HumanInterface:280` | `timeout=10` and graceful fallback in this PR | — |

## 2. Reporting a vulnerability

If you believe you have found a security issue in this codebase, please **do not** open a public issue. Instead, e-mail the maintainer (see the contact in `README.md` — DEVCOM Army Research Laboratory, James Z. Hare) and copy `security@cognition.ai` so it can be tracked through the active federal-security-audit Epic in Jira.

We aim to acknowledge reports within 5 business days.

## 3. Deployment posture (REQUIRED)

This codebase **must not be operated on an untrusted network** in its current form. Until the deferred architectural fixes ship:

1. Run server and clients on the same isolated VLAN, or on a host-only virtual network between research workstations. Do **not** follow the README's "port-forward 5050 on your router" recipe on a network that touches the open internet.
2. Restrict port 5050 with the host firewall to the agreed peer IPs:
   * Linux: `ufw allow from 192.0.2.0/24 to any port 5050 proto tcp`
   * macOS: `pf` rule scoped to the agreed peers
   * Windows: `netsh advfirewall` rule scoped to the agreed peers
3. Treat every connecting client as **fully trusted with code execution on the server** — and vice-versa. The Dill protocol does not enforce a trust boundary.
4. Use the publication of `SECURITY_AUDIT_REPORT.md` to set expectations with downstream researchers about the current posture.

## 4. Cryptographic policy

* Protocol nonces (SYN, SeqNum) use `secrets.randbelow()` (CSPRNG, FIPS 140-2/3 compliant when the underlying OS RNG is FIPS-enabled).
* Game-AI random decision-making (`src/AgentTypes/RandomAgent.py`, `src/AgentTypes/TeamAgents.py`) uses `random.*` and is **not** security-relevant. Each such call site is annotated with `# nosec` and an explanatory comment.
* Hashing for non-security purposes is not used in this codebase.

## 5. Audit logging

`src/security_audit_logging.py` provides a configured `logging.Logger` (`arl_battlespace.security`) that emits ISO-8601 timestamps and severity levels to stderr. It is wired into the newly-narrowed `except` blocks and into the `safe_unpickle()` helper. Log level is configurable via the `ARL_BATTLESPACE_LOG_LEVEL` environment variable.

## 6. Audit history

| Date | Audit | Branch | Report |
|------|-------|--------|--------|
| 2026-05-12 | DISA STIG V5R3 + NIST 800-53 r5 (Cognition AI) | `devin/1778601140-security-audit` | [docs/security-audit/SECURITY_AUDIT_REPORT.md](docs/security-audit/SECURITY_AUDIT_REPORT.md) |
