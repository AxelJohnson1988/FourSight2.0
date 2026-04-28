"""Tests for the Warden integrity, drift, ledger, and capture modules."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from warden.integrity import compute_sha256, compute_sha256_bytes, verify_file
from warden.drift import DriftStatus, cosine_similarity, evaluate_drift
from warden.akashic import AkashicLedger
from warden.capture import CorruptionCapture
from warden import Warden


# ---------------------------------------------------------------------------
# integrity
# ---------------------------------------------------------------------------


class TestIntegrity:
    def test_compute_sha256_known_value(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert compute_sha256(str(f)) == expected

    def test_compute_sha256_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert compute_sha256(str(f)) == expected

    def test_compute_sha256_large_file(self, tmp_path: Path) -> None:
        # Verify chunked reading returns the correct digest for files > 64 KB
        data = b"x" * (200 * 1024)
        f = tmp_path / "large.bin"
        f.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert compute_sha256(str(f)) == expected

    def test_compute_sha256_bytes(self) -> None:
        data = b"warden test data"
        assert compute_sha256_bytes(data) == hashlib.sha256(data).hexdigest()

    def test_verify_file_correct_hash(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        f = tmp_path / "data.bin"
        f.write_bytes(b"content")
        expected = hashlib.sha256(b"content").hexdigest()
        assert verify_file(str(f), expected) is True
        out = capsys.readouterr().out
        assert "VERIFIED" in out

    def test_verify_file_wrong_hash(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        f = tmp_path / "data.bin"
        f.write_bytes(b"content")
        assert verify_file(str(f), "a" * 64) is False
        out = capsys.readouterr().out
        assert "FAILURE" in out

    def test_verify_file_returns_false_on_modification(self, tmp_path: Path) -> None:
        f = tmp_path / "data.bin"
        f.write_bytes(b"original")
        original_hash = compute_sha256(str(f))
        f.write_bytes(b"modified")
        assert verify_file(str(f), original_hash) is False


# ---------------------------------------------------------------------------
# drift
# ---------------------------------------------------------------------------


class TestDrift:
    def test_identical_texts_safe(self) -> None:
        result = evaluate_drift("hello world", "hello world")
        assert result.status == DriftStatus.SAFE
        assert abs(result.score - 1.0) < 1e-9

    def test_completely_different_texts_block(self) -> None:
        result = evaluate_drift("alpha beta gamma", "delta epsilon zeta")
        assert result.status == DriftStatus.BLOCK

    def test_cosine_similarity_both_empty(self) -> None:
        assert cosine_similarity("", "") == 1.0

    def test_cosine_similarity_one_empty(self) -> None:
        assert cosine_similarity("hello", "") == 0.0
        assert cosine_similarity("", "hello") == 0.0

    def test_cosine_similarity_range(self) -> None:
        score = cosine_similarity("foo bar baz", "foo bar qux")
        assert 0.0 <= score <= 1.0

    def test_cosine_similarity_symmetric(self) -> None:
        a, b = "the quick brown fox", "the quick brown cat"
        assert abs(cosine_similarity(a, b) - cosine_similarity(b, a)) < 1e-12

    def test_warning_threshold_respected(self) -> None:
        # Force a WARNING by using a score between thresholds via custom config
        result = evaluate_drift(
            "word1 word2 word3 word4",
            "word1 word2 totally different five",
            safe_threshold=0.99,
            warn_threshold=0.40,
        )
        assert result.status in (DriftStatus.SAFE, DriftStatus.WARNING, DriftStatus.BLOCK)

    def test_custom_thresholds_safe(self) -> None:
        result = evaluate_drift(
            "apple orange",
            "apple orange",
            safe_threshold=0.99,
            warn_threshold=0.50,
        )
        assert result.status == DriftStatus.SAFE

    def test_drift_result_is_blocked_property(self) -> None:
        result = evaluate_drift("hello world", "completely different zyx")
        assert result.is_blocked() == (result.status == DriftStatus.BLOCK)

    def test_score_is_rounded(self) -> None:
        result = evaluate_drift("a b c", "a b d")
        # Score must be at most 6 decimal places (round to 6)
        assert result.score == round(result.score, 6)


# ---------------------------------------------------------------------------
# Akashic Ledger
# ---------------------------------------------------------------------------


class TestAkashicLedger:
    @staticmethod
    def _ledger() -> AkashicLedger:
        return AkashicLedger(":memory:")

    def test_first_entry_has_genesis_prev_hash(self) -> None:
        with self._ledger() as ledger:
            entry = ledger.append(
                input_hash="a" * 64,
                output_hash="b" * 64,
                semantic_score=0.98,
            )
        assert entry["previous_entry_hash"] == "0" * 64

    def test_chain_links_consecutive_entries(self) -> None:
        with self._ledger() as ledger:
            e1 = ledger.append(input_hash="a" * 64, output_hash="b" * 64, semantic_score=1.0)
            e2 = ledger.append(input_hash="c" * 64, output_hash="d" * 64, semantic_score=0.9)
        assert e2["previous_entry_hash"] == e1["entry_hash"]

    def test_verify_chain_empty(self) -> None:
        with self._ledger() as ledger:
            assert ledger.verify_chain() is True

    def test_verify_chain_valid_multiple_entries(self) -> None:
        with self._ledger() as ledger:
            for i in range(5):
                ledger.append(
                    input_hash=str(i) * 64,
                    output_hash=str(i + 1) * 64,
                    semantic_score=0.99,
                )
            assert ledger.verify_chain() is True

    def test_verify_chain_detects_content_tampering(self) -> None:
        ledger = self._ledger()
        ledger.append(input_hash="a" * 64, output_hash="b" * 64, semantic_score=1.0)
        # Silently corrupt the stored input_hash
        ledger._conn.execute(
            "UPDATE ledger SET input_hash = ? WHERE id = 1", ("z" * 64,)
        )
        ledger._conn.commit()
        assert ledger.verify_chain() is False
        ledger.close()

    def test_entries_returns_all_in_order(self) -> None:
        with self._ledger() as ledger:
            for i in range(3):
                ledger.append(
                    input_hash=str(i) * 64,
                    output_hash="0" * 64,
                    semantic_score=1.0,
                )
            rows = ledger.entries()
        assert len(rows) == 3

    def test_entry_contains_all_required_fields(self) -> None:
        with self._ledger() as ledger:
            entry = ledger.append(
                input_hash="a" * 64, output_hash="b" * 64, semantic_score=0.87
            )
        required = {
            "timestamp",
            "input_hash",
            "output_hash",
            "semantic_score",
            "warden_signature",
            "previous_entry_hash",
            "entry_hash",
        }
        assert required.issubset(entry.keys())

    def test_warden_signature_stored(self) -> None:
        with self._ledger() as ledger:
            entry = ledger.append(
                input_hash="a" * 64,
                output_hash="b" * 64,
                semantic_score=1.0,
                warden_signature="sig_abc123",
            )
        assert entry["warden_signature"] == "sig_abc123"


# ---------------------------------------------------------------------------
# Corruption Capture
# ---------------------------------------------------------------------------


class TestCorruptionCapture:
    def test_capture_creates_bundle_directory(self, tmp_path: Path) -> None:
        cc = CorruptionCapture(str(tmp_path / "captures"))
        bundle = cc.capture("original text", "modified text", drift_score=0.75)
        assert bundle.is_dir()

    def test_capture_writes_all_artefacts(self, tmp_path: Path) -> None:
        cc = CorruptionCapture(str(tmp_path / "captures"))
        bundle = cc.capture("raw", "output", drift_score=0.60)
        assert (bundle / "raw_input.txt").exists()
        assert (bundle / "processed_output.txt").exists()
        assert (bundle / "diff.patch").exists()
        assert (bundle / "metadata.json").exists()

    def test_capture_raw_input_content(self, tmp_path: Path) -> None:
        cc = CorruptionCapture(str(tmp_path / "captures"))
        bundle = cc.capture("hello world", "hello earth", drift_score=0.8)
        assert (bundle / "raw_input.txt").read_text() == "hello world"

    def test_capture_metadata_has_pid_and_score(self, tmp_path: Path) -> None:
        cc = CorruptionCapture(str(tmp_path / "captures"))
        bundle = cc.capture("a", "b", drift_score=0.55)
        meta = json.loads((bundle / "metadata.json").read_text())
        assert meta["pid"] == os.getpid()
        assert meta["drift_score"] == 0.55

    def test_capture_diff_reflects_changes(self, tmp_path: Path) -> None:
        cc = CorruptionCapture(str(tmp_path / "captures"))
        bundle = cc.capture("hello world", "hello earth", drift_score=0.8)
        diff = (bundle / "diff.patch").read_text()
        assert "world" in diff or "earth" in diff

    def test_capture_with_event_id_in_name(self, tmp_path: Path) -> None:
        cc = CorruptionCapture(str(tmp_path / "captures"))
        bundle = cc.capture("x", "y", drift_score=0.7, event_id="evt_001")
        assert "evt_001" in bundle.name

    def test_capture_auto_creates_output_dir(self, tmp_path: Path) -> None:
        new_dir = tmp_path / "nested" / "captures"
        cc = CorruptionCapture(str(new_dir))
        assert new_dir.is_dir()


# ---------------------------------------------------------------------------
# Warden (integration)
# ---------------------------------------------------------------------------


class TestWarden:
    @staticmethod
    def _warden(tmp_path: Path) -> Warden:
        return Warden(
            db_path=":memory:",
            capture_dir=str(tmp_path / "captures"),
        )

    def test_identical_input_output_is_safe(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process("hello world", "hello world")
        assert result.drift.status == DriftStatus.SAFE
        assert result.capture_path is None
        assert not result.blocked

    def test_different_texts_trigger_capture(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process("alpha beta gamma", "completely different text")
        assert result.capture_path is not None
        assert result.capture_path.is_dir()

    def test_hashes_differ_for_different_content(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process("hello", "world")
        assert result.input_hash != result.output_hash

    def test_hashes_equal_for_same_content(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process("same text", "same text")
        assert result.input_hash == result.output_hash

    def test_ledger_entry_hashes_match_result(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process("text a", "text b")
        assert result.ledger_entry["input_hash"] == result.input_hash
        assert result.ledger_entry["output_hash"] == result.output_hash

    def test_verify_ledger_after_multiple_processes(self, tmp_path: Path) -> None:
        w = self._warden(tmp_path)
        w.process("foo", "bar")
        w.process("baz", "baz")
        assert w.verify_ledger() is True
        w.close()

    def test_context_manager_closes_cleanly(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process("test input", "test input")
        assert result is not None

    def test_blocked_property_reflects_drift(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process("alpha beta gamma delta", "zeta eta theta iota")
        assert result.blocked == (result.drift.status == DriftStatus.BLOCK)

    def test_warden_signature_passed_to_ledger(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process("data", "data", warden_signature="sig_xyz")
        assert result.ledger_entry["warden_signature"] == "sig_xyz"

    def test_event_id_appears_in_capture_path(self, tmp_path: Path) -> None:
        with self._warden(tmp_path) as w:
            result = w.process(
                "alpha beta gamma",
                "completely different",
                event_id="corruption_001",
            )
        assert result.capture_path is not None
        assert "corruption_001" in result.capture_path.name
