"""What the explain module needs from a language model. The adapter is `snorty.explain.ollama`."""

from typing import Protocol

from snorty.core.models import Alert


class ExplainError(Exception):
    """No explanation could be made. The message says why, in words for the user."""


class Explainer(Protocol):
    model: str  # which model answered, shown next to the text

    async def explain(self, rule_text: str, alert: Alert) -> str:
        """Plain-English reading of the rule that fired. Never receives addresses."""
        ...
