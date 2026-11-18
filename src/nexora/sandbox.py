"""Safe staging workspace; submitted code is never executed."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


class SandboxError(RuntimeError):
    pass


class StagingWorkspace:
    def __init__(self, root: Path):
        self.root=Path(root).resolve(); self.root.mkdir(parents=True,exist_ok=True)
    def stage(self, relative_path: str, content: bytes) -> dict:
        candidate=(self.root/relative_path).resolve()
        if candidate==self.root or self.root not in candidate.parents:
            raise SandboxError("path_escape_denied")
        if not isinstance(content,bytes) or len(content)>2_000_000:
            raise SandboxError("payload_invalid_or_too_large")
        candidate.parent.mkdir(parents=True,exist_ok=True)
        if candidate.exists(): raise SandboxError("staged_file_exists")
        fd=os.open(candidate,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        return {"path":str(candidate.relative_to(self.root)),"sha256":hashlib.sha256(content).hexdigest(),
                "bytes":len(content),"execution":"DISABLED"}
