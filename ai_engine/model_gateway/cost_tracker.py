import os
from dataclasses import dataclass


@dataclass(frozen=True)
class CostEstimate:
    prompt_tokens: int | None
    completion_tokens: int | None
    estimated_usd: float | None


def estimate_cost(provider: str, prompt_tokens: int | None, completion_tokens: int | None) -> CostEstimate:
    if prompt_tokens is None or completion_tokens is None:
        return CostEstimate(prompt_tokens, completion_tokens, None)
    key = provider.upper().replace("-", "_")
    try:
        input_rate = float(os.getenv(f"ND_AI_{key}_INPUT_USD_PER_MILLION", ""))
        output_rate = float(os.getenv(f"ND_AI_{key}_OUTPUT_USD_PER_MILLION", ""))
    except ValueError:
        return CostEstimate(prompt_tokens, completion_tokens, None)
    if input_rate < 0 or output_rate < 0:
        return CostEstimate(prompt_tokens, completion_tokens, None)
    amount = (prompt_tokens * input_rate + completion_tokens * output_rate) / 1_000_000
    return CostEstimate(prompt_tokens, completion_tokens, round(amount, 8))
