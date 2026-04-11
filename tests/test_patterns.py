"""Tests for phoenix_scanner.patterns."""

import pytest
from phoenix_scanner.patterns import PATTERNS, Pattern, build_keyword_pattern


def _find(pattern: Pattern, text: str) -> list[str]:
    return [m.group(0) for m in pattern.regex.finditer(text)]


def test_sha256_detects_valid_hex():
    sha = "a" * 64
    p = next(p for p in PATTERNS if p.name == "sha256_hex")
    assert _find(p, f"hash={sha}") == [sha]


def test_sha256_ignores_63_chars():
    p = next(p for p in PATTERNS if p.name == "sha256_hex")
    assert _find(p, "a" * 63) == []


def test_sha256_ignores_65_chars():
    p = next(p for p in PATTERNS if p.name == "sha256_hex")
    # 65 contiguous hex chars → no word-boundary match
    assert _find(p, "a" * 65) == []


def test_ed25519_sig_detects_128_hex():
    sig = "b" * 128
    p = next(p for p in PATTERNS if p.name == "ed25519_sig_hex")
    assert _find(p, f" {sig} ") == [sig]


def test_ed25519_sig_ignores_64_chars():
    p = next(p for p in PATTERNS if p.name == "ed25519_sig_hex")
    assert _find(p, "b" * 64) == []


def test_ipfs_cidv0_detected():
    cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
    p = next(p for p in PATTERNS if p.name == "ipfs_cidv0")
    assert _find(p, f" {cid} ") == [cid]


def test_ipfs_cidv1_detected():
    cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
    p = next(p for p in PATTERNS if p.name == "ipfs_cidv1")
    assert _find(p, f" {cid} ") == [cid]


def test_master_proof_hash_detected():
    sha = "c" * 64
    p = next(p for p in PATTERNS if p.name == "master_proof_hash")
    assert sha in _find(p, f"Master Proof Hash: {sha}")[0]


def test_op_return_payload_detected():
    payload = "414c454501" + "d" * 64
    p = next(p for p in PATTERNS if p.name == "op_return_payload")
    assert _find(p, payload) == [payload]


def test_build_keyword_pattern_matches():
    kp = build_keyword_pattern(["verify_and_timestamp.sh", "Master Proof Hash"])
    assert kp is not None
    assert kp.regex.search("found verify_and_timestamp.sh in repo")
    assert kp.regex.search("MASTER PROOF HASH present")


def test_build_keyword_pattern_returns_none_for_empty():
    assert build_keyword_pattern([]) is None
