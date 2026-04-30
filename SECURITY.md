# Security Policy

This repository targets federal/defense deployment and is subject to the STIG
Application Security and Development STIG (Version 5, Release 3) and NIST
SP 800-53 Rev. 5 controls. All code changes that touch authentication,
network transport, serialization, or user-facing input must cite the relevant
STIG / NIST references in the pull request description.

## Controls in scope

| Reference | Requirement | Where enforced |
| --- | --- | --- |
| **STIG V-220631** (SI-10) | Whitelist input validation on every untrusted input | `src/secure_envelope.py` (`jsonschema.validate` of every received payload) |
| **STIG V-220632** (SI-10) | Sanitize / parameterize data crossing a trust boundary | `src/secure_envelope.py` (JSON-only wire format; no `pickle`/`eval` on received bytes) |
| **STIG V-220633** (SC-28) | Encryption at rest (AES-256) | Wave 4 — persisted game-state files still use `dill` on disk; to be replaced with AES-256 sealed envelopes |
| **STIG V-220634** (SC-8)  | Encryption in transit (TLS 1.2+) | Wave 4 — mTLS for the `ServerWithUI.py` TCP listener |
| **NIST SI-10** | Information input validation | `src/secure_envelope.py:unwrap` |
| **NIST SC-8**  | Transmission confidentiality and integrity | HMAC-SHA256 signature + `jsonschema` on every recv frame |
| **NIST SC-28** | Protection of information at rest | Wave 4 |
| **CWE-502** | Deserialization of Untrusted Data | Remediated in Wave 3: no code path deserializes attacker-controlled bytes via `pickle`/`dill` |

## Wave 3 — replace `pickle.loads` / `dill.loads` on TCP with HMAC-signed JSON

Wave 1+2 (PR #7) closed repo hygiene and added CI security workflows. Wave 3
(this change) eliminates CWE-502 (Deserialization of Untrusted Data) in every
call site that deserializes bytes coming from a TCP socket.

* New module: [`src/secure_envelope.py`](src/secure_envelope.py).
    * `wrap(payload, secret)` — canonical JSON body, `ts` + 128-bit random
      `nonce`, 8-byte big-endian length prefix, HMAC-SHA256 signature.
    * `unwrap(blob, secret, schema)` — constant-time HMAC verify
      (`hmac.compare_digest`), strict JSON parse, ±30 s replay window check,
      `jsonschema.validate` against the caller-supplied schema.
    * `pack` / `unpack` — convenience wrappers for call sites that need to
      transmit non-dict Python values.
    * Raises `EnvelopeError` on any failure — no pickle, no `eval`, no code
      execution path on the receive side.
* Unit tests: [`tests/test_secure_envelope.py`](tests/test_secure_envelope.py)
  — 27 cases covering round-trip, signature tamper, body tamper, wrong secret,
  schema mismatch, replay-window rejection (past + future clock skew), frame
  truncation, short-blob rejection, non-bytes/non-dict rejection, nonce
  uniqueness, `to_jsonable` coercion of common Python shapes, and
  `BATTLESPACE_AGENT_SECRET` env-var override.

## HMAC shared secret — `BATTLESPACE_AGENT_SECRET`

The envelope is authenticated with HMAC-SHA256 under a symmetric key shared
between each server and its authorized agents/clients. The key is read from
the `BATTLESPACE_AGENT_SECRET` environment variable at process start.

If the variable is not set, `secure_envelope.shared_secret()` falls back to a
**development-only** hard-coded value (`battlespace-dev-only-shared-secret-change-me`).
Production deployments MUST set the environment variable before launching any
server, client, or agent process. The fallback is marked in-source with
`# TODO: rotate via SECRETS_MANAGER`.

### Rotation runbook

Rotate the shared secret at least every 90 days, and immediately on any
suspected compromise, operator departure, or machine image leak.

1. **Generate a new key (32 bytes of CSPRNG entropy, base64-encoded):**

   ```bash
   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
   ```

2. **Stage the new key in the secrets manager** (AWS Secrets Manager / HashiCorp
   Vault / GCP Secret Manager — whichever the deployment uses). Example for
   AWS:

   ```bash
   aws secretsmanager put-secret-value \
     --secret-id battlespace/agent-hmac \
     --secret-string "$NEW_KEY"
   ```

3. **Drain clients.** Notify all agents / UI clients that a key rotation
   window is open, and wait for in-flight turns to complete.

4. **Cut over.** On each server host:

   ```bash
   export BATTLESPACE_AGENT_SECRET="$NEW_KEY"
   systemctl restart battlespace-server   # or equivalent launcher
   ```

5. **Push the same `BATTLESPACE_AGENT_SECRET` to every authorized agent /
   UI process** (`HumanInterface.py`, `RemoteAgent.py`, `interface.py`).
   Any process still using the old key will have its frames rejected at
   `unwrap` with `EnvelopeError("HMAC signature mismatch")`.

6. **Verify.** Tail the server log for `EnvelopeError` entries and confirm
   rejections have stopped. Remove the previous key from the secrets manager
   once no rejections have been seen for 24 hours.

7. **Revoke the prior key** in the secrets manager and audit-log the event.

### Things the rotation runbook does NOT cover (Wave 4)

* **Per-agent keys.** Today the key is a single shared secret; any
  authenticated agent can forge frames as any other. Wave 4 will replace
  this with per-agent X.509 client certificates terminated in mTLS.
* **At-rest encryption of persisted game-state.** Wave 4 will replace the
  on-disk `dill` snapshots with AES-256 sealed envelopes.
* **Transport confidentiality.** Today the envelope is authenticated but
  not encrypted; the JSON body is visible on the wire. Wave 4 adds TLS 1.2+
  on the `ServerWithUI.py` listener (STIG V-220634 / NIST SC-8).

## Reporting a vulnerability

Report suspected vulnerabilities to the project maintainers via a private
channel; do not open a public issue. Include a minimal reproduction, the
affected commit SHA, and any relevant scanner output.
