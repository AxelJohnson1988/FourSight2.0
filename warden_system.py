"""
Warden Full System v1

A machine-verifiable trust pipeline:
  Canonical Payload → SHA-256 → Ed25519 Signature → Hash-Chain Ledger

The private key is loaded from the WARDEN_PRIVATE_KEY_HEX environment variable
(preferred, for automated pipelines) or from the file path specified by
WARDEN_PRIVATE_KEY_FILE (defaults to "warden_signing_key.priv").

Setup (one-time):
    pip install cryptography
    python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
with open('warden_signing_key.priv', 'wb') as f:
    f.write(key.private_bytes_raw())
print('Key written to warden_signing_key.priv')
"

Usage:
    python warden_system.py --text "Test payload"
    python warden_system.py --file evidence.mp4
    python warden_system.py --scan /path/to/logs
    python warden_system.py --verify
"""

import os
import re
import json
import time
import hashlib
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# =========================
# CONFIG
# =========================
LEDGER_FILE = os.environ.get("WARDEN_LEDGER_FILE", "warden_ledger.json")
PRIVATE_KEY_FILE = os.environ.get("WARDEN_PRIVATE_KEY_FILE", "warden_signing_key.priv")
PUBLIC_KEY_FILE = os.environ.get("WARDEN_PUBLIC_KEY_FILE", "warden_signing_key.pub")

CHUNK_SIZE = 65536

SEARCH_PATTERNS = [
    r"\b[a-f0-9]{64}\b",  # SHA-256 hashes
    r"OP_RETURN",
    r"Ed25519",
    r"CID[a-zA-Z0-9]+",
]


# =========================
# CORE — HASHING
# =========================
def compute_sha256_bytes(data: bytes) -> str:
    if not data:
        raise ValueError("Cannot hash empty data")
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    digest = sha256.hexdigest()
    # Reject null digest (empty file)
    if digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        raise ValueError("File is empty; refusing to hash")
    return digest


# =========================
# CANONICAL PAYLOAD
# =========================
def build_canonical_payload(text_input: str | None, file_bytes: bytes | None) -> bytes:
    """Build a deterministic byte payload from optional text and/or file bytes."""
    text_part = text_input.encode("utf-8") if text_input else b""
    file_part = file_bytes if file_bytes else b""
    return (
        b"TEXT_START\n"
        + text_part
        + b"\nTEXT_END\nFILE_START\n"
        + file_part
        + b"\nFILE_END"
    )


# =========================
# KEY MANAGEMENT
# =========================
def _raw_private_key_bytes() -> bytes:
    """Return the 32-byte raw Ed25519 private key from env var or key file."""
    hex_key = os.environ.get("WARDEN_PRIVATE_KEY_HEX")
    if hex_key:
        raw = bytes.fromhex(hex_key.strip())
        if len(raw) != 32:
            raise ValueError(
                "WARDEN_PRIVATE_KEY_HEX must be exactly 32 bytes (64 hex chars)"
            )
        return raw

    if not os.path.exists(PRIVATE_KEY_FILE):
        raise FileNotFoundError(
            f"Private key file '{PRIVATE_KEY_FILE}' not found. "
            "Generate one with: python warden_system.py --keygen"
        )
    with open(PRIVATE_KEY_FILE, "rb") as f:
        raw = f.read()
    if len(raw) != 32:
        raise ValueError(
            f"Private key file must contain exactly 32 raw bytes; got {len(raw)}"
        )
    return raw


def load_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_raw_private_key_bytes())


def load_public_key() -> Ed25519PublicKey:
    """Load the public key from the .pub file, or derive it from the private key."""
    if os.path.exists(PUBLIC_KEY_FILE):
        from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
        with open(PUBLIC_KEY_FILE, "rb") as f:
            raw = f.read()
        return _ed.Ed25519PublicKey.from_public_bytes(raw)
    # Derive from private key
    return load_private_key().public_key()


def keygen() -> None:
    """Generate an Ed25519 key pair and write to disk."""
    key = Ed25519PrivateKey.generate()
    raw_priv = key.private_bytes_raw()
    raw_pub = key.public_key().public_bytes_raw()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(raw_priv)
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(raw_pub)

    print(f"[Warden] Private key written to: {PRIVATE_KEY_FILE}")
    print(f"[Warden] Public  key written to: {PUBLIC_KEY_FILE}")
    print(
        "[Warden] Keep the private key secret. "
        "Distribute the public key for verification."
    )


# =========================
# SIGNING
# =========================
def sign_hash(private_key: Ed25519PrivateKey, hash_hex: str) -> str:
    signature = private_key.sign(bytes.fromhex(hash_hex))
    return signature.hex()


# =========================
# SANITY CHECK
# =========================
_SUSPICIOUS_TERMS = [b"advertisement", b"promo", b"spam"]


def sanity_check(data: bytes) -> str:
    """Return 'OK' or a warning string. Raises ValueError on empty payload."""
    if not data:
        raise ValueError("Empty payload")

    lowered = data.lower()
    flagged = [term.decode() for term in _SUSPICIOUS_TERMS if term in lowered]
    if flagged:
        return f"WARNING: Suspicious content pattern(s) detected: {', '.join(flagged)}"

    return "OK"


# =========================
# LEDGER (HASH CHAIN)
# =========================
def load_ledger() -> list:
    if not os.path.exists(LEDGER_FILE):
        return []
    with open(LEDGER_FILE, "r") as f:
        return json.load(f)


def save_ledger(ledger: list) -> None:
    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=2)


def get_previous_hash(ledger: list) -> str:
    if not ledger:
        return "GENESIS"
    return ledger[-1]["chain_hash"]


def compute_chain_hash(current_hash: str, previous_hash: str) -> str:
    return hashlib.sha256((previous_hash + current_hash).encode()).hexdigest()


def append_to_ledger(entry: dict) -> None:
    ledger = load_ledger()
    ledger.append(entry)
    save_ledger(ledger)


# =========================
# VERIFICATION
# =========================
def verify_ledger() -> list[dict]:
    """
    Verify the entire ledger:
    - Chain integrity (each chain_hash is correctly computed from previous)
    - Ed25519 signature over the payload_hash
    Returns a list of result dicts, one per entry.
    """
    ledger = load_ledger()
    if not ledger:
        print("[Warden] Ledger is empty.")
        return []

    public_key = load_public_key()
    results = []
    previous_hash = "GENESIS"

    for i, entry in enumerate(ledger):
        result = {"index": i, "timestamp": entry.get("timestamp"), "errors": []}

        # Chain integrity
        expected_chain = compute_chain_hash(entry["payload_hash"], previous_hash)
        if expected_chain != entry["chain_hash"]:
            result["errors"].append(
                f"Chain hash mismatch: expected {expected_chain}, "
                f"got {entry['chain_hash']}"
            )

        # Signature verification
        try:
            public_key.verify(
                bytes.fromhex(entry["signature"]),
                bytes.fromhex(entry["payload_hash"]),
            )
        except InvalidSignature:
            result["errors"].append("Invalid Ed25519 signature")
        except Exception as exc:
            result["errors"].append(f"Signature check error: {exc}")

        result["valid"] = len(result["errors"]) == 0
        previous_hash = entry["chain_hash"]
        results.append(result)

    return results


# =========================
# WARDEN CORE PROCESS
# =========================
def warden_process(
    text_input: str | None = None, file_path: str | None = None
) -> dict:
    """
    Main pipeline:
      build payload → sanity check → hash → sign → chain → ledger
    """
    if not text_input and not file_path:
        raise ValueError("Provide at least one of --text or --file")

    file_bytes: bytes | None = None
    if file_path:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        if not file_bytes:
            raise ValueError(f"File '{file_path}' is empty")

    if text_input is not None and not text_input.strip():
        raise ValueError("Text input must not be empty or whitespace only")

    payload = build_canonical_payload(text_input, file_bytes)
    status = sanity_check(payload)
    payload_hash = compute_sha256_bytes(payload)

    private_key = load_private_key()
    signature = sign_hash(private_key, payload_hash)

    ledger = load_ledger()
    previous_hash = get_previous_hash(ledger)
    chain_hash = compute_chain_hash(payload_hash, previous_hash)

    record = {
        "timestamp": time.time(),
        "payload_hash": payload_hash,
        "signature": signature,
        "previous_hash": previous_hash,
        "chain_hash": chain_hash,
        "sanity_status": status,
        "input_type": "file" if file_path else "text",
    }

    append_to_ledger(record)
    return record


# =========================
# FORENSIC SCANNER
# =========================
def _scan_file(path: str) -> list[dict]:
    results = []
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for pattern in SEARCH_PATTERNS:
                    if re.search(pattern, line):
                        results.append(
                            {
                                "file": path,
                                "line": lineno,
                                "match": line.rstrip("\n"),
                                "pattern": pattern,
                            }
                        )
    except OSError:
        pass
    return results


def scan_directory(root_path: str) -> list[dict]:
    files = [
        str(p)
        for p in Path(root_path).rglob("*")
        if p.is_file()
    ]
    results: list[dict] = []
    with ThreadPoolExecutor() as executor:
        for res in executor.map(_scan_file, files):
            results.extend(res)
    return results


# =========================
# CLI ENTRY
# =========================
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Warden Full System v1 — cryptographic trust pipeline"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", type=str, help="Text payload to hash and sign")
    group.add_argument("--file", type=str, help="File to hash and sign")
    group.add_argument(
        "--scan", type=str, metavar="DIR", help="Directory to scan for cryptographic artifacts"
    )
    group.add_argument(
        "--verify", action="store_true", help="Verify integrity of the hash-chain ledger"
    )
    group.add_argument(
        "--keygen", action="store_true", help="Generate a new Ed25519 key pair"
    )

    args = parser.parse_args()

    if args.keygen:
        keygen()
        return

    if args.scan:
        print(f"[Warden] Scanning '{args.scan}' for cryptographic artifacts...")
        findings = scan_directory(args.scan)
        print(json.dumps(findings[:20], indent=2))
        if len(findings) > 20:
            print(f"... and {len(findings) - 20} more finding(s).")
        return

    if args.verify:
        print("[Warden] Verifying ledger integrity...")
        results = verify_ledger()
        ok = all(r["valid"] for r in results)
        print(json.dumps(results, indent=2))
        if ok:
            print(f"\n[Warden] ✓ All {len(results)} entries valid.")
        else:
            print("\n[Warden] ✗ Verification FAILED — see errors above.")
        return

    result = warden_process(
        text_input=args.text,
        file_path=args.file,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
