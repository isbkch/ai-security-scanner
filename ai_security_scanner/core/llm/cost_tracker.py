"""LLM API cost tracking and estimation."""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TokenUsage:
    """Token usage statistics for a single API call."""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    model: str
    provider: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CostEstimate:
    """Cost estimate for API usage."""

    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    prompt_cost: float
    completion_cost: float
    total_cost: float
    currency: str = "USD"


class LLMCostTracker:
    """Track and estimate costs for LLM API usage."""

    # Pricing per 1K tokens (as of January 2024)
    # Update these prices periodically
    PRICING = {
        "openai": {
            "gpt-4-turbo-preview": {"prompt": 0.01, "completion": 0.03},
            "gpt-4": {"prompt": 0.03, "completion": 0.06},
            "gpt-4-32k": {"prompt": 0.06, "completion": 0.12},
            "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
            "gpt-3.5-turbo-16k": {"prompt": 0.003, "completion": 0.004},
        },
        "anthropic": {
            "claude-3-opus": {"prompt": 0.015, "completion": 0.075},
            "claude-3-sonnet": {"prompt": 0.003, "completion": 0.015},
            "claude-3-haiku": {"prompt": 0.00025, "completion": 0.00125},
            "claude-2.1": {"prompt": 0.008, "completion": 0.024},
            "claude-2": {"prompt": 0.008, "completion": 0.024},
            "claude-instant-1.2": {"prompt": 0.0008, "completion": 0.0024},
        },
        "azure": {
            # Azure OpenAI pricing mirrors OpenAI
            "gpt-4": {"prompt": 0.03, "completion": 0.06},
            "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
        },
        "huggingface": {
            # HuggingFace Inference API is typically free or very cheap
            "default": {"prompt": 0.0, "completion": 0.0},
        },
        "ollama": {
            # Ollama is local and free
            "default": {"prompt": 0.0, "completion": 0.0},
        },
    }

    def __init__(self) -> None:
        """Initialize cost tracker."""
        self.usage_history: List[TokenUsage] = []
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cost = 0.0
        self.requests_by_provider: Dict[str, int] = {}
        self.cost_by_provider: Dict[str, float] = {}

    def track_usage(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> CostEstimate:
        """Track token usage and estimate cost.

        Args:
            provider: LLM provider name (openai, anthropic, etc.)
            model: Model name
            prompt_tokens: Number of prompt tokens used
            completion_tokens: Number of completion tokens used

        Returns:
            Cost estimate for this usage
        """
        total_tokens = prompt_tokens + completion_tokens

        # Record usage
        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=model,
            provider=provider,
        )
        self.usage_history.append(usage)

        # Update totals
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens

        # Update provider counts
        self.requests_by_provider[provider] = self.requests_by_provider.get(provider, 0) + 1

        # Estimate cost
        estimate = self.estimate_cost(provider, model, prompt_tokens, completion_tokens)

        # Update total cost
        self.total_cost += estimate.total_cost

        # Update cost by provider
        self.cost_by_provider[provider] = (
            self.cost_by_provider.get(provider, 0.0) + estimate.total_cost
        )

        logger.debug(
            f"Tracked usage: {provider}/{model} - "
            f"{prompt_tokens} prompt + {completion_tokens} completion tokens = "
            f"${estimate.total_cost:.4f}"
        )

        return estimate

    def estimate_cost(
        self, provider: str, model: str, prompt_tokens: int, completion_tokens: int
    ) -> CostEstimate:
        """Estimate cost for token usage.

        Args:
            provider: LLM provider name
            model: Model name
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            Detailed cost estimate
        """
        provider_lower = provider.lower()
        model_lower = model.lower()

        # Get pricing for provider and model
        if provider_lower not in self.PRICING:
            logger.warning(f"Unknown provider '{provider}', using zero cost")
            pricing = {"prompt": 0.0, "completion": 0.0}
        else:
            provider_pricing = self.PRICING[provider_lower]

            # Find matching model pricing
            pricing = None
            for model_key in provider_pricing:
                if model_key in model_lower:
                    pricing = provider_pricing[model_key]
                    break

            if pricing is None:
                # Use default or first available pricing
                if "default" in provider_pricing:
                    pricing = provider_pricing["default"]
                else:
                    pricing = list(provider_pricing.values())[0]
                    logger.warning(
                        f"No exact pricing for model '{model}', using default for {provider}"
                    )

        # Calculate costs (pricing is per 1K tokens)
        prompt_cost = (prompt_tokens / 1000.0) * pricing["prompt"]
        completion_cost = (completion_tokens / 1000.0) * pricing["completion"]
        total_cost = prompt_cost + completion_cost

        return CostEstimate(
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            prompt_cost=prompt_cost,
            completion_cost=completion_cost,
            total_cost=total_cost,
        )

    def get_summary(self) -> Dict[str, any]:
        """Get summary of usage and costs.

        Returns:
            Dictionary with usage statistics and cost breakdown
        """
        return {
            "total_requests": len(self.usage_history),
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "total_cost_usd": round(self.total_cost, 4),
            "requests_by_provider": self.requests_by_provider,
            "cost_by_provider": {
                provider: round(cost, 4) for provider, cost in self.cost_by_provider.items()
            },
            "avg_cost_per_request": (
                round(self.total_cost / len(self.usage_history), 4) if self.usage_history else 0.0
            ),
        }

    def get_provider_breakdown(self, provider: str) -> Dict[str, any]:
        """Get detailed breakdown for a specific provider.

        Args:
            provider: Provider name

        Returns:
            Usage and cost breakdown for the provider
        """
        provider_usage = [u for u in self.usage_history if u.provider.lower() == provider.lower()]

        if not provider_usage:
            return {
                "provider": provider,
                "requests": 0,
                "total_tokens": 0,
                "total_cost": 0.0,
            }

        total_prompt = sum(u.prompt_tokens for u in provider_usage)
        total_completion = sum(u.completion_tokens for u in provider_usage)

        # Calculate cost
        total_cost = 0.0
        for usage in provider_usage:
            estimate = self.estimate_cost(
                usage.provider, usage.model, usage.prompt_tokens, usage.completion_tokens
            )
            total_cost += estimate.total_cost

        return {
            "provider": provider,
            "requests": len(provider_usage),
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "total_tokens": total_prompt + total_completion,
            "total_cost_usd": round(total_cost, 4),
            "avg_tokens_per_request": round(
                (total_prompt + total_completion) / len(provider_usage)
            ),
            "avg_cost_per_request": round(total_cost / len(provider_usage), 4),
        }

    def reset(self) -> None:
        """Reset all tracked usage and costs."""
        self.usage_history.clear()
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cost = 0.0
        self.requests_by_provider.clear()
        self.cost_by_provider.clear()
        logger.info("Cost tracker reset")

    def export_to_dict(self) -> Dict:
        """Export full tracking data.

        Returns:
            Dictionary with all usage history and summary
        """
        return {
            "summary": self.get_summary(),
            "usage_history": [
                {
                    "timestamp": usage.timestamp.isoformat(),
                    "provider": usage.provider,
                    "model": usage.model,
                    "prompt_tokens": usage.prompt_tokens,
                    "completion_tokens": usage.completion_tokens,
                    "total_tokens": usage.total_tokens,
                    "estimated_cost": self.estimate_cost(
                        usage.provider,
                        usage.model,
                        usage.prompt_tokens,
                        usage.completion_tokens,
                    ).total_cost,
                }
                for usage in self.usage_history
            ],
        }


# Global cost tracker instance
_global_tracker: Optional[LLMCostTracker] = None


def get_global_tracker() -> LLMCostTracker:
    """Get or create the global cost tracker instance.

    Returns:
        Global cost tracker
    """
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = LLMCostTracker()
    return _global_tracker


def track_llm_usage(
    provider: str, model: str, prompt_tokens: int, completion_tokens: int
) -> CostEstimate:
    """Track LLM usage using the global tracker.

    Args:
        provider: LLM provider name
        model: Model name
        prompt_tokens: Prompt tokens used
        completion_tokens: Completion tokens used

    Returns:
        Cost estimate
    """
    tracker = get_global_tracker()
    return tracker.track_usage(provider, model, prompt_tokens, completion_tokens)


def get_cost_summary() -> Dict:
    """Get cost summary from global tracker.

    Returns:
        Cost summary dictionary
    """
    tracker = get_global_tracker()
    return tracker.get_summary()
