# Security Policy

## Reporting a Vulnerability

This is a research codebase from the U.S. Army Research Laboratory. To report a
suspected security vulnerability, please open a GitHub issue tagged
`security` or contact the maintainers privately. Do not disclose details
publicly until the maintainers have had a chance to investigate.

## Known Security Posture (DSOP shift-left)

This repository is a research / wargame simulation. Several network-side
behaviors documented in the DSOP shift-left scan must be hardened before any
deployment outside an isolated research host:

- Network-side `pickle` / `dill` deserialization (CWE-502).
- Plaintext TCP listener with no peer authentication (CWE-306, CWE-319).
- No structured audit logging (NIST AU-2/AU-3, STIG V-220635).

See the DSOP shift-left bundle for the full POA&M and remediation roadmap.
