"""Validate structured CLI output before rendering."""
import json


def validate_json_output(value, *, max_bytes: int = 1_000_000) -> str:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if len(rendered.encode("utf-8")) > max_bytes:
        raise ValueError("output_too_large")
    return rendered
