# Operational diagnostics

## Read-only doctor

Run:

```bash
nexora doctor
```

The command checks audit-chain integrity, kill-switch state, SQLite registry
quick-check, settings validation, specification/matrix completeness, settings
authorization readiness and OS sandbox preflight. It does not initialize
storage, create missing files, change settings, clear the kill switch, contact
the network or execute code.

Exit codes: 0 = no reported blockers, 2 = critical integrity/configuration
failure, 3 = readable system with outstanding blockers or emergency stop.

## Isolated kill-switch self-test

Run:

```bash
nexora kill-switch-test
```

The self-test creates a disposable temporary marker and checks clear, engage,
restart persistence and clear-after-restart behavior. It never touches
`data/KILL` or the configured production marker.

This is not proof of worker termination, execution freeze, physical-device
behavior or recovery authorization. Those require separate integration tests.


## Dashboard

The loopback-only web dashboard exposes the same diagnostic report at
`GET /api/doctor`. The endpoint is GET-only and does not initialize storage.



## Expanded terminal dashboard

Run nexora tui. The read-only menu now includes specification/matrix
readiness, doctor diagnostics, source-backed family inventory, explicitly
declared dependency edges and settings authorization readiness in addition
to the existing system, audit, proposal, registry and evidence views.

All views are diagnostics only. Missing specifications remain missing;
unknown matrix pairs remain blocking; a policy file is not approval; and
the dashboard does not initialize storage or expose mutation/execution
controls.
