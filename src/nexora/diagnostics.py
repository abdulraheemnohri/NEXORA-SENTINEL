"""Read-only local diagnostics."""
from __future__ import annotations
import os
import platform
import shutil
import sys
from pathlib import Path

def collect(data_dir: Path) -> dict:
    path=Path(data_dir)
    usage=shutil.disk_usage(path if path.exists() else path.parent)
    return {"python":sys.version.split()[0],"platform":platform.platform(),"architecture":platform.machine(),
            "data_dir_exists":path.exists(),"data_dir":str(path),"disk_total_bytes":usage.total,
            "disk_free_bytes":usage.free,"pid":os.getpid(),"network_access":"not_probed"}
