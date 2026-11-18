# Sandbox readiness (preflight only)

NEXORA's staging workspace is a path-contained file staging area, not an OS
sandbox. The `nexora sandbox-check` command reports prerequisite availability
without launching Bubblewrap, creating namespaces, executing payloads, or
changing host configuration.

## Status meanings

- `UNAVAILABLE`: the host is not a qualified Linux desktop/server host or the
  Bubblewrap executable is not discoverable.
- `UNVERIFIED`: a Linux host and Bubblewrap executable were detected, but
  namespace creation, filesystem/network isolation, resource limits, credential
  exclusion and adversarial escape resistance have not been proven.
- `READY` is intentionally never emitted by this preflight implementation.

A binary on PATH is not evidence that user namespaces are enabled or that
Bubblewrap can enforce the required policy. This check does not probe by
running Bubblewrap because a probe would itself cross an execution boundary.

## Mandatory gates still outstanding

1. A reviewed Bubblewrap invocation profile with explicit mount allowlists.
2. Verified user, mount, PID and network namespace behavior on each supported host.
3. A read-only root, bounded writable workspace and no host home/credential/socket mounts.
4. OS-enforced CPU, memory, process-count and wall-clock limits.
5. Environment scrubbing and descriptor inheritance controls.
6. Adversarial tests for symlinks, path traversal, namespace failure, network escape,
   host file access, resource exhaustion and cleanup.
7. Independent security review and actual-device qualification for Android Debian.

If any guarantee is missing, execution must remain blocked. There is no
unsandboxed fallback. The existing staging API remains the only supported
workspace operation and never executes staged content.

## Command

```sh
nexora sandbox-check
```

The report is diagnostic only. It does not enable the sandbox setting, authorize
a tool, or certify the host as secure.
