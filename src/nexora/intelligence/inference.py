"""Inference is disabled until a reviewed local runtime adapter is installed."""


class InferenceDisabled(PermissionError):
    pass


def generate(*_args, **_kwargs):
    raise InferenceDisabled("model_inference_not_configured")
