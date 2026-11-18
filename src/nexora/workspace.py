"""Project workspace helpers with path containment checks."""
from pathlib import Path


class Workspace:
    def __init__(self, root: Path):
        self.root=Path(root).resolve(); self.root.mkdir(parents=True,exist_ok=True)
    def resolve(self, relative: str) -> Path:
        target=(self.root/relative).resolve()
        if target==self.root or self.root not in target.parents:
            raise ValueError("workspace_path_escape_denied")
        return target
    def list_files(self, *, limit: int=500) -> list[str]:
        if not 1<=limit<=5000: raise ValueError("limit_out_of_range")
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*") if p.is_file())[:limit]
