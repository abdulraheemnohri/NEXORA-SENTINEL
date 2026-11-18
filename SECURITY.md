# Security policy

Report vulnerabilities privately to the repository maintainer. Do not publish exploit details before a fix is available.

## Security invariants
- Fail closed on unknown actions, missing evidence and integrity failures.
- No autonomous execution or privilege expansion.
- Keep approval private keys outside the repository with restrictive permissions.
- Trust public keys only after independent fingerprint verification.
- Treat local audit chains as tamper-evident, not tamper-proof.
- Treat operator labels as metadata, not identity proof.

## Scope limitations
This is an evolving safety foundation. It is not a hardened sandbox, secure boot system, hardware-backed identity provider, or production autonomous agent.
