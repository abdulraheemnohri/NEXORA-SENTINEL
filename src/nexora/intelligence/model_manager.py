"""Explicit local model inventory; never downloads or executes model files."""
from pathlib import Path


class ModelManager:
    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir).resolve()
        self.model_dir.mkdir(parents=True, exist_ok=True)

    def inventory(self) -> list[dict]:
        return [
            {"name": path.name, "path": str(path), "bytes": path.stat().st_size, "runtime": "NOT_LOADED"}
            for path in sorted(self.model_dir.iterdir()) if path.is_file()
        ]

    def resolve(self, name: str) -> Path:
        if not isinstance(name, str) or not name or Path(name).name != name:
            raise ValueError("model_name_invalid")
        target = (self.model_dir / name).resolve()
        if target.parent != self.model_dir or not target.is_file():
            raise FileNotFoundError("local_model_not_found")
        return target
