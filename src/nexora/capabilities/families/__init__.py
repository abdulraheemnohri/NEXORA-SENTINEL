"""Canonical family identifiers; no missing capability content is synthesized."""
FAMILY_CODES = tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZ") + tuple("A" + x for x in "ABCDEFGHIJKLMN")

def validate_family(code: str) -> str:
    if code not in FAMILY_CODES:
        raise ValueError("unknown_capability_family")
    return code

__all__ = ["FAMILY_CODES", "validate_family"]
