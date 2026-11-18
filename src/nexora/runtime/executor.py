"""Execution is deliberately unavailable until isolation and approvals are reviewed."""


class ExecutionDisabled(PermissionError):
    pass


def execute(*_args, **_kwargs):
    raise ExecutionDisabled("execution_disabled_in_safety_kernel_milestone")
