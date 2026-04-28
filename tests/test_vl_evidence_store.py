"""Tests for gpam.vl_llm.evidence_store."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpam.vl_llm.evidence_store import (
    FilesystemEvidenceStore,
    InMemoryEvidenceStore,
)
from gpam.vl_llm.types import artifact_hash_for, evidence_id_for


# ---------------------------------------------------------------------------
# InMemoryEvidenceStore
# ---------------------------------------------------------------------------


def test_add_artifact_returns_hash() -> None:
    store = InMemoryEvidenceStore()
    result = store.add_artifact(source_uri="https://a.com", data="Hello world")
    assert result.artifact_hash == artifact_hash_for("Hello world")


def test_add_artifact_returns_evidence_id() -> None:
    store = InMemoryEvidenceStore()
    result = store.add_artifact(source_uri="https://a.com", data="Hello")
    expected_eid = evidence_id_for("https://a.com", artifact_hash_for("Hello"))
    assert result.evidence_id == expected_eid


def test_add_artifact_idempotent() -> None:
    store = InMemoryEvidenceStore()
    r1 = store.add_artifact(source_uri="https://a.com", data="X")
    r2 = store.add_artifact(source_uri="https://a.com", data="X")
    assert r1.evidence_id == r2.evidence_id
    assert r2.already_existed is True
    assert len(store) == 1


def test_add_artifact_different_data_different_id() -> None:
    store = InMemoryEvidenceStore()
    r1 = store.add_artifact(source_uri="https://a.com", data="A")
    r2 = store.add_artifact(source_uri="https://a.com", data="B")
    assert r1.evidence_id != r2.evidence_id
    assert len(store) == 2


def test_add_artifact_bytes() -> None:
    store = InMemoryEvidenceStore()
    result = store.add_artifact(source_uri="https://a.com", data=b"raw bytes")
    assert len(result.artifact_hash) == 64


def test_cite_returns_item() -> None:
    store = InMemoryEvidenceStore()
    r = store.add_artifact(source_uri="https://b.com", data="Content", extract="short")
    item = store.cite(r.evidence_id)
    assert item is not None
    assert item.source_uri == "https://b.com"
    assert item.extract == "short"


def test_cite_unknown_id_returns_none() -> None:
    store = InMemoryEvidenceStore()
    assert store.cite("nonexistent") is None


def test_extract_capped_at_2000_chars() -> None:
    store = InMemoryEvidenceStore()
    long_extract = "x" * 5000
    r = store.add_artifact(source_uri="https://c.com", data="d", extract=long_extract)
    item = store.cite(r.evidence_id)
    assert len(item.extract) == 2000


def test_list_ids() -> None:
    store = InMemoryEvidenceStore()
    store.add_artifact(source_uri="https://a.com", data="A")
    store.add_artifact(source_uri="https://b.com", data="B")
    ids = store.list_ids()
    assert len(ids) == 2


def test_first_add_not_already_existed() -> None:
    store = InMemoryEvidenceStore()
    r = store.add_artifact(source_uri="https://a.com", data="first")
    assert r.already_existed is False


# ---------------------------------------------------------------------------
# FilesystemEvidenceStore
# ---------------------------------------------------------------------------


def test_fs_store_add_and_cite(tmp_path: Path) -> None:
    store = FilesystemEvidenceStore(tmp_path / "evidence")
    r = store.add_artifact(source_uri="https://x.com", data="Filesystem test")
    item = store.cite(r.evidence_id)
    assert item is not None
    assert item.source_uri == "https://x.com"
    assert item.artifact_hash == r.artifact_hash


def test_fs_store_is_idempotent(tmp_path: Path) -> None:
    store = FilesystemEvidenceStore(tmp_path / "evidence")
    r1 = store.add_artifact(source_uri="https://x.com", data="same data")
    r2 = store.add_artifact(source_uri="https://x.com", data="same data")
    assert r1.evidence_id == r2.evidence_id
    assert r2.already_existed is True
    assert len(store) == 1


def test_fs_store_artifact_file_exists(tmp_path: Path) -> None:
    store = FilesystemEvidenceStore(tmp_path / "evidence")
    r = store.add_artifact(source_uri="https://x.com", data="artifact content")
    artifact_path = tmp_path / "evidence" / "artifacts" / f"{r.artifact_hash}.bin"
    assert artifact_path.exists()


def test_fs_store_cite_unknown_returns_none(tmp_path: Path) -> None:
    store = FilesystemEvidenceStore(tmp_path / "evidence")
    assert store.cite("nonexistent") is None


def test_fs_store_list_ids(tmp_path: Path) -> None:
    store = FilesystemEvidenceStore(tmp_path / "evidence")
    store.add_artifact(source_uri="https://a.com", data="A")
    store.add_artifact(source_uri="https://b.com", data="B")
    assert len(store.list_ids()) == 2
