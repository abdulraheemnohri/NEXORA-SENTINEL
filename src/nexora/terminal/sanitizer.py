"""Normalize terminal text and reject control characters."""
import unicodedata


def sanitize_text(value: str, *, max_chars: int = 20000) -> str:
    if not isinstance(value, str) or len(value) > max_chars:
        raise ValueError("terminal_text_invalid_or_too_large")
    normalized = unicodedata.normalize("NFC", value)
    if any(ord(char) < 32 and char not in "\t\n" for char in normalized):
        raise ValueError("terminal_control_character_denied")
    return normalized
