"""Canary release gate; enabling remains a separate signed human decision."""


def evaluate_canary(*, sample_count: int, failures: int, threshold: float = 0.0) -> dict:
    if type(sample_count) is not int or sample_count < 1 or type(failures) is not int or not 0 <= failures <= sample_count:
        raise ValueError("canary_counts_invalid")
    if type(threshold) not in (int, float) or not 0 <= threshold < 1:
        raise ValueError("canary_threshold_invalid")
    rate = failures / sample_count
    return {"failure_rate": rate, "eligible_for_human_review": rate <= threshold, "automatic_promotion": False}
