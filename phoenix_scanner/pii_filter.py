"""PII sanitization layer (Priority 5) — placeholder module for future LLM integration.

When an external AI/LLM API is wired into the pipeline, **all text must pass
through** :func:`sanitize_pii` before being sent.  This module integrates
Microsoft Presidio for entity detection and replaces identified PII with typed
placeholders so that neither raw names, emails, phone numbers, nor similar
sensitive data ever leave the host.

Usage
-----
>>> from phoenix_scanner.pii_filter import sanitize_pii
>>> clean = sanitize_pii("Contact John Doe at john@example.com")
>>> # clean == "Contact [PERSON] at [EMAIL_ADDRESS]"

Dependencies
------------
This module requires the ``presidio-analyzer`` and ``presidio-anonymizer``
packages plus a spaCy language model.  Install them with::

    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg

These are **not** listed as core dependencies of ``phoenix-scanner`` because
the current scanner operates on local files and never sends text to an external
API.  Add them to the ``[project.optional-dependencies]`` ``llm`` extra in
``pyproject.toml`` when wiring up LLM integration.

Behaviour when Presidio is not installed
-----------------------------------------
:func:`sanitize_pii` raises :exc:`ImportError` with a clear installation
message rather than silently passing raw text through.  This is intentional:
callers that reach this function without Presidio installed have a
misconfigured pipeline and must fix the dependency gap rather than accidentally
leaking PII.
"""

from __future__ import annotations


# Placeholder type — replaced by the real Presidio type when available.
_AnalyzerEngine = object
_AnonymizerEngine = object

_analyzer: _AnalyzerEngine | None = None
_anonymizer: _AnonymizerEngine | None = None


def _load_engines() -> tuple[object, object]:
    """Lazy-load Presidio engines; raises ImportError if not installed."""
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore[import]
        from presidio_anonymizer import AnonymizerEngine  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "presidio-analyzer and presidio-anonymizer are required for PII filtering. "
            "Install them with: pip install presidio-analyzer presidio-anonymizer "
            "and then run: python -m spacy download en_core_web_lg"
        ) from exc

    return AnalyzerEngine(), AnonymizerEngine()


def sanitize_pii(text: str, *, language: str = "en") -> str:
    """Replace PII entities in *text* with typed placeholders.

    Parameters
    ----------
    text:
        Raw input that may contain personally identifiable information.
    language:
        BCP-47 language code passed to Presidio's analyzer.  Defaults to
        ``"en"`` (English).

    Returns
    -------
    str
        A copy of *text* with all detected PII replaced by bracketed entity
        labels (e.g. ``[PERSON]``, ``[EMAIL_ADDRESS]``, ``[PHONE_NUMBER]``).

    Raises
    ------
    ImportError
        If ``presidio-analyzer`` or ``presidio-anonymizer`` are not installed.
    """
    global _analyzer, _anonymizer  # noqa: PLW0603
    if _analyzer is None or _anonymizer is None:
        _analyzer, _anonymizer = _load_engines()

    results = _analyzer.analyze(text=text, language=language)  # type: ignore[union-attr]

    from presidio_anonymizer.entities import OperatorConfig  # type: ignore[import]

    operators = {
        entity.entity_type: OperatorConfig(
            "replace", {"new_value": f"[{entity.entity_type}]"}
        )
        for entity in results
    }
    anonymized = _anonymizer.anonymize(  # type: ignore[union-attr]
        text=text, analyzer_results=results, operators=operators
    )
    return anonymized.text
