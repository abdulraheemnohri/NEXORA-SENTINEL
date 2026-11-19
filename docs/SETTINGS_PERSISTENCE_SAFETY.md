# Settings persistence safety

NEXORA settings currently expose inspection and validation interfaces. This document records the persistence guarantees of the low-level `Settings.save()` helper; it does not introduce a settings editor, API endpoint, policy mutation command, or feature-enable control.

## Atomic persistence

- Validate the complete settings object before touching the destination.
- Serialize JSON or YAML fully before creating a temporary file.
- Create the temporary file in the destination directory so replacement stays on the same filesystem.
- Restrict the temporary file to owner-only permissions where the platform supports POSIX modes.
- Flush and fsync file contents before replacement.
- Replace the destination atomically with `os.replace`.
- On POSIX, fsync the containing directory after replacement to persist the directory entry.
- Remove temporary files after failures; a failed replacement leaves the previous destination untouched.

## Path handling

- Reject a symlink destination, including a dangling symlink.
- Reject an existing destination that is not a regular file.
- The implementation rechecks for a symlink immediately before replacement. It does not claim protection against a privileged attacker concurrently replacing parent directories or changing filesystem mount topology.

## Governance boundary

Atomic file replacement is not authorization. No CLI, web, TUI, scheduler, model, or agent path is added to call this method as a policy editor. The settings inspection interface remains read-only. The default autonomy level remains L0; scheduler, sandbox and network flags remain false by default.

A future settings-change workflow still requires a reviewed per-setting authorization matrix, explicit human confirmation, append-only before/after audit records, backup/rollback semantics, and tests proving that invalid or unauthorized changes cannot be applied. Unknown policy relationships remain blocked rather than inferred.


## Read-only change preview

`nexora settings diff --config CURRENT --candidate PROPOSED` compares two validated configurations and reports changed fields. A non-empty diff is marked `REVIEW_REQUIRED`; authorization remains `NOT_EVALUATED` because a reviewed per-setting authorization matrix has not been approved. The command has no apply mode and cannot mutate configuration or enable any feature. A matching candidate reports `NO_CHANGES`. Missing/invalid candidates fail closed.

Settings inspection also uses `lstat()` and rejects symlink configuration paths, including dangling symlinks. A genuinely missing path may use built-in defaults; permission and other I/O failures are not converted into defaults.
