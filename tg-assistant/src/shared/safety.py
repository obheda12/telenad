"""
Content sanitization and input validation for the query pipeline.

Provides two synchronous components that sit at the boundary where
untrusted synced messages enter Claude's context:

- **ContentSanitizer**: Detects known prompt-injection patterns in synced
  message text.  Detection only (logs warnings) — does not modify content.
  The primary defense is XML boundary markers in ``querybot.llm``.

- **InputValidator**: Validates user input (message length, null bytes,
  whitespace ratio) before it enters the query pipeline.

Both are stdlib-only (``re``), synchronous, and add <0.1 ms of latency.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("shared.safety")


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SanitizeResult:
    """Result of running ContentSanitizer on a piece of text."""

    content: str
    warnings: List[str] = field(default_factory=list)
    flagged: bool = False


@dataclass
class InputValidationResult:
    """Result of running InputValidator on user input."""

    valid: bool
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ContentSanitizer — prompt injection detection (logging only)
# ---------------------------------------------------------------------------

# Patterns that are unambiguously adversarial — zero false positives in
# normal Telegram chat.  Deliberately conservative: we exclude phrases
# like "system:", "assistant:", "forget everything" because those appear
# in everyday conversation.
_INJECTION_PATTERNS = [
    ("ignore_previous_instructions", re.compile(
        r"(?i)ignore\s+(all\s+)?previous\s+instructions"
    )),
    ("llm_inst_token", re.compile(
        r"\[INST\]|\[/INST\]"
    )),
    ("llm_special_token", re.compile(
        r"<\|[a-z_]*\|>"
    )),
    ("null_byte", re.compile(
        r"\x00"
    )),
]


class ContentSanitizer:
    """Detect prompt-injection patterns in synced message text.

    This is a **detection-only** layer — flagged content is logged but
    not modified.  The primary mitigation is the XML boundary markers
    added in ``querybot.llm._format_context()``.

    Args:
        enabled: When ``False``, bypasses all checks (returns clean result).
    """

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._patterns = _INJECTION_PATTERNS

    def sanitize(self, text: str) -> SanitizeResult:
        """Scan *text* for known injection patterns.

        Returns a :class:`SanitizeResult` with the original content
        unchanged, plus any warnings and a ``flagged`` boolean.
        """
        if not self._enabled:
            return SanitizeResult(content=text)

        warnings: List[str] = []
        for name, pattern in self._patterns:
            if pattern.search(text):
                warnings.append(name)

        flagged = len(warnings) > 0
        if flagged:
            logger.warning(
                "Injection pattern(s) detected: %s (text_length=%d)",
                ", ".join(warnings),
                len(text),
            )

        return SanitizeResult(content=text, warnings=warnings, flagged=flagged)


# ---------------------------------------------------------------------------
# InputValidator — user message validation
# ---------------------------------------------------------------------------


class InputValidator:
    """Validate user input before it enters the query pipeline.

    Args:
        max_length: Maximum allowed message length in characters.
    """

    def __init__(self, max_length: int = 4000) -> None:
        self._max_length = max_length

    def validate(self, text: Optional[str]) -> InputValidationResult:
        """Validate *text* and return an :class:`InputValidationResult`."""
        if not text:
            return InputValidationResult(
                valid=False,
                error_message="Message is empty.",
            )

        if "\x00" in text:
            return InputValidationResult(
                valid=False,
                error_message="Message contains invalid characters.",
            )

        if len(text) > self._max_length:
            return InputValidationResult(
                valid=False,
                error_message=(
                    f"Message too long ({len(text)} chars). "
                    f"Maximum is {self._max_length}."
                ),
            )

        warnings: List[str] = []
        if len(text) >= 100:
            whitespace_count = sum(1 for c in text if c.isspace())
            if whitespace_count / len(text) > 0.9:
                warnings.append("Message is mostly whitespace.")

        return InputValidationResult(valid=True, warnings=warnings)
