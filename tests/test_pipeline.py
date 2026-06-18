"""Tests for phoenix_scanner.pipeline (Phase 3 — YAML Pipeline Orchestration)."""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML required for pipeline tests")

from phoenix_scanner.pipeline import run_pipeline  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


def test_pipeline_missing_steps_key(tmp_path: Path):
    f = _write_yaml(tmp_path / "bad.yaml", "foo: bar\n")
    with pytest.raises(ValueError, match="'steps'"):
        run_pipeline(f)


def test_pipeline_steps_not_a_list(tmp_path: Path):
    f = _write_yaml(tmp_path / "bad.yaml", "steps: not_a_list\n")
    with pytest.raises(ValueError):
        run_pipeline(f)


def test_pipeline_unknown_step_type(tmp_path: Path, tmp_path_factory):
    root = tmp_path_factory.mktemp("data")
    (root / "file.txt").write_text("content")
    f = _write_yaml(
        tmp_path / "bad.yaml",
        f"steps:\n  - unknown_step:\n      foo: bar\n",
    )
    with pytest.raises(ValueError, match="Unknown pipeline step"):
        run_pipeline(f)


def test_pipeline_malformed_step_entry(tmp_path: Path):
    f = _write_yaml(
        tmp_path / "bad.yaml",
        "steps:\n  - [this, is, not, a, mapping]\n",
    )
    with pytest.raises(ValueError, match="exactly one key"):
        run_pipeline(f)


# ---------------------------------------------------------------------------
# crawl-only pipeline
# ---------------------------------------------------------------------------


def test_pipeline_crawl_only(tmp_path: Path, tmp_path_factory):
    root = tmp_path_factory.mktemp("scan_root")
    (root / "doc.txt").write_text("hello world")
    f = _write_yaml(
        tmp_path / "pipeline.yaml",
        f"steps:\n  - crawl:\n      root: '{root}'\n",
    )
    results = run_pipeline(f)
    assert "0:crawl" in results
    assert results["0:crawl"]["entries"] >= 1


# ---------------------------------------------------------------------------
# crawl → scan pipeline
# ---------------------------------------------------------------------------


def test_pipeline_crawl_scan(tmp_path: Path, tmp_path_factory):
    root = tmp_path_factory.mktemp("scan_root")
    sha = "a" * 64
    (root / "evidence.txt").write_text(f"hash={sha}")

    f = _write_yaml(
        tmp_path / "pipeline.yaml",
        f"steps:\n"
        f"  - crawl:\n"
        f"      root: '{root}'\n"
        f"  - scan: {{}}\n",
    )
    results = run_pipeline(f)
    assert results["0:crawl"]["entries"] >= 1
    assert results["1:scan"]["findings"] >= 1


# ---------------------------------------------------------------------------
# scan requires crawl
# ---------------------------------------------------------------------------


def test_pipeline_scan_without_crawl_raises(tmp_path: Path):
    f = _write_yaml(tmp_path / "pipeline.yaml", "steps:\n  - scan: {}\n")
    with pytest.raises(RuntimeError, match="crawl"):
        run_pipeline(f)


# ---------------------------------------------------------------------------
# crawl → scan → anchor (with text)
# ---------------------------------------------------------------------------


def test_pipeline_crawl_scan_anchor_with_text(tmp_path: Path, tmp_path_factory):
    root = tmp_path_factory.mktemp("scan_root")
    sha = "b" * 64
    (root / "proof.txt").write_text(sha)

    f = _write_yaml(
        tmp_path / "pipeline.yaml",
        f"steps:\n"
        f"  - crawl:\n"
        f"      root: '{root}'\n"
        f"  - scan: {{}}\n"
        f"  - anchor:\n"
        f"      text: 'pipeline integration test'\n",
    )
    results = run_pipeline(f)
    anchor_result = results["2:anchor"]
    assert "sha256" in anchor_result
    assert "op_return_payload" in anchor_result
    assert anchor_result["op_return_payload"].startswith("414c454501")


# ---------------------------------------------------------------------------
# ledger requires scan findings
# ---------------------------------------------------------------------------


def test_pipeline_ledger_without_findings_raises(tmp_path: Path, tmp_path_factory):
    """Ledger step fails when no findings file was produced."""
    root = tmp_path_factory.mktemp("empty_root")
    # No file with recognisable patterns → write_findings skips → no findings file
    (root / "no_patterns.txt").write_text("no sha256 here at all plain text")

    f = _write_yaml(
        tmp_path / "pipeline.yaml",
        f"steps:\n"
        f"  - crawl:\n"
        f"      root: '{root}'\n"
        f"  - scan: {{}}\n"
        f"  - ledger: {{}}\n",
    )
    with pytest.raises(RuntimeError, match="ledger"):
        run_pipeline(f)


# ---------------------------------------------------------------------------
# anchor requires text or ledger
# ---------------------------------------------------------------------------


def test_pipeline_anchor_without_text_or_ledger_raises(tmp_path: Path, tmp_path_factory):
    root = tmp_path_factory.mktemp("scan_root")
    (root / "file.txt").write_text("hello")

    f = _write_yaml(
        tmp_path / "pipeline.yaml",
        f"steps:\n"
        f"  - crawl:\n"
        f"      root: '{root}'\n"
        f"  - scan: {{}}\n"
        f"  - anchor: {{}}\n",  # no text, no ledger
    )
    with pytest.raises(RuntimeError, match="anchor"):
        run_pipeline(f)


# ---------------------------------------------------------------------------
# Full pipeline: crawl → scan → ledger → anchor
# ---------------------------------------------------------------------------


def test_pipeline_full_chain(tmp_path: Path, tmp_path_factory):
    root = tmp_path_factory.mktemp("scan_root")
    sha = "c" * 64
    (root / "evidence.txt").write_text(sha)

    f = _write_yaml(
        tmp_path / "pipeline.yaml",
        f"steps:\n"
        f"  - crawl:\n"
        f"      root: '{root}'\n"
        f"  - scan: {{}}\n"
        f"  - ledger: {{}}\n"
        f"  - anchor:\n"
        f"      text: 'full chain test'\n",
    )
    results = run_pipeline(f)
    assert "0:crawl" in results
    assert "1:scan" in results
    assert "2:ledger" in results
    assert "3:anchor" in results
    assert results["3:anchor"]["sha256"]


# ---------------------------------------------------------------------------
# Result keys are indexed correctly
# ---------------------------------------------------------------------------


def test_pipeline_result_keys_are_indexed(tmp_path: Path, tmp_path_factory):
    root = tmp_path_factory.mktemp("scan_root")
    (root / "f.txt").write_text("x")

    f = _write_yaml(
        tmp_path / "pipeline.yaml",
        f"steps:\n  - crawl:\n      root: '{root}'\n",
    )
    results = run_pipeline(f)
    # key format is "<index>:<step_type>"
    assert list(results.keys()) == ["0:crawl"]
