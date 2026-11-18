# Threat model

Controls: unknown actions denied; runtime policy mutation disabled; emergency stop blocks decisions; audit append refuses a broken hash chain; no generated-code executor or network tools exist in v0.1.0.

Limitations: local hash chaining is tamper-evident, not tamper-proof. A full-file rewrite can recompute hashes. The witness is a separate local receipt file, not a remote/hardware trust anchor. Multi-process append locking, signatures, OS sandboxing and formal verification remain unimplemented.
