"""Fail-closed oversight primitives for NEXORA Sentinel."""
from __future__ import annotations
import hashlib, json, os, tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

class KillSwitch:
    def __init__(self, marker: Path): self.marker = marker
    def is_engaged(self) -> bool: return self.marker.exists()
    def engage(self, reason: str = "operator") -> None:
        self.marker.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".KILL.", dir=self.marker.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write((reason.strip() or "operator")[:256] + "\n"); f.flush(); os.fsync(f.fileno())
            os.chmod(tmp, 0o600); os.replace(tmp, self.marker)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
    def clear(self) -> None: self.marker.unlink(missing_ok=True)

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

class AuditLog:
    def __init__(self, path: Path):
        self.path = path; path.parent.mkdir(parents=True, exist_ok=True); path.touch(exist_ok=True)
        try: os.chmod(path, 0o600)
        except OSError: pass
    def entries(self) -> list[dict]:
        result = []
        with self.path.open(encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if line.strip():
                    try: item = json.loads(line)
                    except json.JSONDecodeError as e: raise ValueError(f"Corrupt audit line {n}") from e
                    if not isinstance(item, dict): raise ValueError(f"Invalid audit line {n}")
                    result.append(item)
        return result
    def verify(self) -> bool:
        previous = GENESIS
        try:
            for item in self.entries():
                body = {k:v for k,v in item.items() if k != "hash"}
                expected = hashlib.sha256((previous + canonical(body)).encode()).hexdigest()
                if item.get("previous_hash") != previous or item.get("hash") != expected: return False
                previous = expected
            return True
        except (OSError, ValueError, TypeError): return False
    def append(self, event: str, payload: dict) -> dict:
        if not self.verify(): raise RuntimeError("Audit integrity failure; append refused")
        rows = self.entries(); prev = rows[-1]["hash"] if rows else GENESIS
        body = {"sequence":len(rows)+1,"event":event,"payload":payload,"previous_hash":prev}
        record = {**body,"hash":hashlib.sha256((prev+canonical(body)).encode()).hexdigest()}
        with self.path.open("a",encoding="utf-8") as f:
            f.write(canonical(record)+"\n"); f.flush(); os.fsync(f.fileno())
        return record

class Witness:
    """Separate local receipt stream; not a remote or hardware trust anchor."""
    def __init__(self, path: Path): self.path=path; path.parent.mkdir(parents=True,exist_ok=True); path.touch(exist_ok=True)
    def attest(self, event_hash: str, event_type: str) -> dict:
        if len(event_hash)!=64 or any(c not in "0123456789abcdef" for c in event_hash):
            raise ValueError("Expected lowercase SHA-256 digest")
        body={"event_hash":event_hash,"event_type":event_type}
        receipt={**body,"witness_hash":hashlib.sha256(canonical(body).encode()).hexdigest()}
        with self.path.open("a",encoding="utf-8") as f: f.write(canonical(receipt)+"\n"); f.flush()
        return receipt

@dataclass(frozen=True)
class Decision:
    action: str
    allowed: bool
    reason: str
    autonomy_level: str = "L0"
    def to_dict(self): return asdict(self)

IMMUTABLE_SAFETY_BASELINE = (
 "safety_precedes_all_other_priorities","unknown_actions_are_denied",
 "proposal_is_not_mutation","privilege_expansion_requires_human_approval",
 "high_and_critical_risk_require_human_approval","kill_switch_blocks_all_actions",
 "audit_integrity_failure_blocks_actions","autonomy_defaults_to_l0",
 "generated_code_requires_sandbox","every_decision_is_observable")

class PolicyKernel:
    def __init__(self, kill: KillSwitch):
        self.kill=kill
        self.registered={"system.status":"low","audit.verify":"low","filesystem.read":"medium"}
    def register_action(self, *_):
        raise PermissionError("Runtime policy mutation disabled in v0.1.0")
    def evaluate(self, action: str, risk: str, human_approved: bool=False) -> Decision:
        if self.kill.is_engaged(): return Decision(action,False,"kill_switch_engaged")
        if action not in self.registered: return Decision(action,False,"unknown_action_denied")
        levels={"low":0,"medium":1,"high":2,"critical":3}
        if risk not in levels: return Decision(action,False,"invalid_risk_denied")
        if levels[risk]>levels[self.registered[action]]: return Decision(action,False,"risk_exceeds_registration")
        if risk!="low" and not human_approved: return Decision(action,False,"explicit_approval_required")
        return Decision(action,True,"approved_by_v0_1_baseline")
