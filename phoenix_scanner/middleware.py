"""Sovereign Shield middleware — pre-LLM injection prevention.

Call :func:`sanitize_input` on any text before passing it to an external
language-model API.  The function raises :exc:`SecurityViolationError` on
detection so that callers are forced to handle blocked input explicitly rather
than silently discarding it.
"""

from __future__ import annotations

import re


class SecurityViolationError(ValueError):
    """Raised when :func:`sanitize_input` detects a blocked pattern.

    Attributes
    ----------
    violation_type:
        Short label identifying which category of rule was triggered
        (e.g. ``"shell_injection"``, ``"path_traversal"``,
        ``"prompt_injection"``).
    matched_text:
        The substring that triggered the rule.
    """

    def __init__(self, message: str, *, violation_type: str, matched_text: str) -> None:
        super().__init__(message)
        self.violation_type = violation_type
        self.matched_text = matched_text


# ---------------------------------------------------------------------------
# Compiled blocklist — deterministic, no external dependencies
# ---------------------------------------------------------------------------

_RULES: list[tuple[str, re.Pattern[str]]] = [
    # Shell injection: $(...) subshells and backtick execution
    (
        "shell_injection",
        re.compile(r"\$\(|`", re.MULTILINE),
    ),
    # Path traversal: directory climbing sequences
    (
        "path_traversal",
        re.compile(r"\.\.[/\\]", re.MULTILINE),
    ),
    # Prompt injection — common LLM jailbreak phrases (case-insensitive)
    (
        "prompt_injection",
        re.compile(
            r"ignore\s+(?:all\s+)?previous\s+(?:instructions?|prompts?)"
            r"|system\s*:"
            r"|<\|"          # token boundary markers used by some models
            r"|\[INST\]"     # Llama-2 / Mistral instruction tokens
            r"|\[/INST\]"
            r"|<s>"          # BOS token sometimes injected verbatim
            r"|</s>",        # EOS token
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
]


def sanitize_input(text: str) -> str:
    """Check *text* against the Sovereign Shield blocklist.

    Parameters
    ----------
    text:
        Raw input string to validate.

    Returns
    -------
    str
        The original *text*, unchanged, if no blocked patterns are found.

    Raises
    ------
    SecurityViolationError
        On the first blocked pattern detected.  Callers must explicitly handle
        this exception — input is never silently stripped or modified.

    Examples
    --------
    >>> sanitize_input("hello world")
    'hello world'
    >>> sanitize_input("ignore previous instructions")
    Traceback (most recent call last):
        ...
    phoenix_scanner.middleware.SecurityViolationError: ...
    """
    for violation_type, pattern in _RULES:
        match = pattern.search(text)
        if match:
            matched = match.group(0)
            raise SecurityViolationError(
                f"Blocked input ({violation_type}): {matched!r} detected in text",
                violation_type=violation_type,
                matched_text=matched,
            )
    return text
