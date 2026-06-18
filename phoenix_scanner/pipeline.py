"""Declarative YAML pipeline runner for FourSight 2.0 (Phase 3).

Treats pipeline definitions as *Policy-as-Code*: a human-readable, version-
controlled YAML file drives the full ``crawl → scan → ledger → anchor``
sequence without requiring any custom Python scripting.

YAML format
-----------
::

    steps:
      - crawl:
          root: "/mnt/secure_vault"
          text_only: true
          exclude: ["*.tmp", ".git/*"]
      - scan:
          redact: true
          patterns_dir: "./custom_patterns/fips_140"
          max_bytes: 10485760
      - ledger:
          sign: true
      - anchor:
          text: "Weekly Compliance Audit"

Steps are executed in order.  State is passed automatically between steps:

* ``crawl`` sets ``manifest_path`` → consumed by ``scan``
* ``scan`` sets ``findings_path`` → consumed by ``ledger``
* ``ledger`` sets ``summary_path`` → consumed by ``anchor``

Example
-------
::

    from pathlib import Path
    from phoenix_scanner.pipeline import run_pipeline

    results = run_pipeline(Path("phoenix_pipeline.yaml"))
    print(results)

Dependencies
------------
Requires ``pyyaml``.  Install with::

    pip install pyyaml

or::

    pip install phoenix-scanner[pipeline]
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_KNOWN_STEPS = frozenset({"crawl", "scan", "ledger", "anchor"})


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and validate the top-level structure of a pipeline YAML file."""
    try:
        import yaml  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "PyYAML is required for pipeline orchestration. "
            "Install it with: pip install pyyaml"
        ) from exc

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict) or "steps" not in data:
        raise ValueError(
            f"Pipeline file {path} must contain a top-level 'steps' list."
        )
    if not isinstance(data["steps"], list):
        raise ValueError(f"'steps' in {path} must be a list.")
    return data


def run_pipeline(yaml_path: Path) -> dict[str, Any]:
    """Execute a declarative YAML pipeline definition.

    Parameters
    ----------
    yaml_path:
        Path to the ``phoenix_pipeline.yaml`` (or similar) file.

    Returns
    -------
    dict
        A mapping of ``"<index>:<step_type>"`` keys to per-step result dicts.

    Raises
    ------
    ImportError
        If PyYAML is not installed.
    ValueError
        If the pipeline file is structurally invalid.
    RuntimeError
        If a required step prerequisite is missing at runtime.
    """
    data = _load_yaml(yaml_path)
    steps: list[dict[str, Any]] = data["steps"]

    # Shared working directory for all intermediate artifacts
    work_dir = Path(tempfile.mkdtemp(prefix="phoenix_pipeline_"))
    state: dict[str, Any] = {"work_dir": work_dir}
    results: dict[str, Any] = {}

    for i, step_def in enumerate(steps):
        if not isinstance(step_def, dict) or len(step_def) != 1:
            raise ValueError(
                f"Step {i} must be a mapping with exactly one key (the step type); "
                f"got {step_def!r}"
            )
        step_type, step_cfg = next(iter(step_def.items()))
        step_cfg = step_cfg or {}

        if step_type not in _KNOWN_STEPS:
            raise ValueError(
                f"Unknown pipeline step {step_type!r}. "
                f"Valid steps: {sorted(_KNOWN_STEPS)}"
            )

        logger.info("Pipeline step %d/%d: %s", i + 1, len(steps), step_type)

        handler = {
            "crawl": _run_crawl,
            "scan": _run_scan,
            "ledger": _run_ledger,
            "anchor": _run_anchor,
        }[step_type]

        result = handler(step_cfg, state)
        results[f"{i}:{step_type}"] = result
        logger.info("Step %d (%s) → %s", i, step_type, result)

    return results


# ---------------------------------------------------------------------------
# Step handlers
# ---------------------------------------------------------------------------


def _run_crawl(cfg: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from phoenix_scanner.config import Config
    from phoenix_scanner.crawler import crawl, write_manifest

    work_dir: Path = state["work_dir"]
    manifest_path = work_dir / "manifest.jsonl"

    phoenix_cfg = Config(
        root_dir=Path(cfg.get("root", ".")),
        text_only=bool(cfg.get("text_only", False)),
        exclude_globs=list(cfg.get("exclude", ["**/.git/**"])),
        max_file_size=int(cfg.get("max_file_size", 10 * 1024 * 1024)),
        manifest_path=manifest_path,
    )
    entries = crawl(phoenix_cfg, max_workers=int(cfg.get("workers", 4)))
    write_manifest(entries, manifest_path)

    state["manifest_path"] = manifest_path
    state["entries"] = entries
    return {"entries": len(entries), "manifest": str(manifest_path)}


def _run_scan(cfg: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from phoenix_scanner.config import Config
    from phoenix_scanner.crawler import read_manifest
    from phoenix_scanner.registry import PatternRegistry
    from phoenix_scanner.scanner import scan, write_findings

    work_dir: Path = state["work_dir"]
    findings_path = work_dir / "findings.jsonl"

    manifest_path: Path | None = state.get("manifest_path")
    if manifest_path is None:
        raise RuntimeError("'scan' step requires a preceding 'crawl' step.")

    phoenix_cfg = Config(
        redact_matches=bool(cfg.get("redact", False)),
        max_bytes_per_file=int(cfg.get("max_bytes", 5 * 1024 * 1024)),
        findings_path=findings_path,
    )

    entries = state.get("entries") or read_manifest(manifest_path)

    registry: PatternRegistry | None = None
    patterns_dir_str: str | None = cfg.get("patterns_dir")
    if patterns_dir_str:
        registry = PatternRegistry()
        registry.load_from_dir(Path(patterns_dir_str))

    findings = scan(entries, phoenix_cfg, pattern_registry=registry)
    write_findings(findings, findings_path)

    state["findings_path"] = findings_path
    state["findings"] = findings
    return {"findings": len(findings), "output": str(findings_path)}


def _run_ledger(cfg: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from phoenix_scanner.ledger import write_ledger

    work_dir: Path = state["work_dir"]
    summary_path = work_dir / "summary.json"

    findings_path: Path | None = state.get("findings_path")
    if findings_path is None or not findings_path.exists():
        raise RuntimeError(
            "'ledger' step requires a preceding 'scan' step that produced findings."
        )

    summary = write_ledger(findings_path, summary_path)
    state["summary_path"] = summary_path
    state["summary"] = summary
    return {
        "summary": str(summary_path),
        "total_findings": summary.get("total_findings", 0),
    }


def _run_anchor(cfg: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from phoenix_scanner.anchoring import anchor
    from phoenix_scanner.config import Config

    phoenix_cfg = Config()
    text: str = str(cfg.get("text", ""))
    file_path: Path | None = None

    summary_path: Path | None = state.get("summary_path")
    if summary_path and summary_path.exists():
        file_path = summary_path

    if not text.strip() and file_path is None:
        raise RuntimeError(
            "'anchor' step requires either a preceding 'ledger' step or a 'text' key."
        )

    result = anchor(text=text, file_path=file_path, config=phoenix_cfg)
    state["anchor_result"] = result
    return dict(result)
