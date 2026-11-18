"""Parse a restricted command line without invoking a shell."""
import shlex

ALLOWED_COMMANDS = {"status", "catalog-check", "audit", "check", "backup", "verify-backup"}


def parse_command(command: str) -> list[str]:
    if not isinstance(command, str) or not command.strip() or len(command) > 4096:
        raise ValueError("command_input_invalid")
    if any(char in command for char in (";", "|", "&", "$", chr(96), "\n", "\r")):
        raise ValueError("shell_metacharacter_denied")
    tokens = shlex.split(command, posix=True)
    if not tokens or tokens[0] not in ALLOWED_COMMANDS:
        raise ValueError("command_not_allowlisted")
    return tokens
