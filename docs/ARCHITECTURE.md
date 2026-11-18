# Architecture

NEXORA Sentinel is organized as a local-first, layered Python system. The public package modules separate core planning, oversight, governance, capability metadata, runtime boundaries, intelligence contracts, memory, evolution gates, terminal validation, interfaces and storage.

## Trust and control flow

1. A user goal is converted to an inert proposal by the planner.
2. The policy kernel evaluates a known action against the static allowlist and emergency stop.
3. Governance checks use only explicit source-backed relations; unknown matrix cells block and escalate.
4. Capability lifecycle transitions require sequential evidence. APPROVED and ENABLED additionally require a scoped Ed25519 receipt signed by an enrolled key.
5. Runtime modules currently queue proposals or stage bytes only. They do not execute shell commands, tools or generated code.
6. Audit events and SQLite records provide local observability. Local witness receipts are not independent hardware attestations.

## Persistence

SQLite databases use WAL and FULL synchronous mode where implemented. Registry backup uses SQLite's online backup API, then records a SHA-256 manifest. Restore verifies the manifest and SQLite integrity before atomically publishing to a destination that must not already exist.

## Modularity

Subpackages expose stable import surfaces. Existing implementation modules remain authoritative where facades delegate to them. The project must not fork policy logic across multiple packages.

## Current limits

There is no autonomous agent loop, model inference runtime, network listener, OS sandbox, or permission-granted tool executor. The TUI, web and API packages are namespace boundaries only. These limits are intentional, not implied capabilities.
