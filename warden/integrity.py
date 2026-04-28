"""SHA-256 file-integrity helpers for the Warden engine.

Usage::

    from warden.integrity import compute_sha256, verify_file

    # Generate a hash to store in your ledger
    stored_hash = compute_sha256("Video_Evidence_Documentation.mp4")

    # Later — verify the file hasn't changed
    ok = verify_file("Video_Evidence_Documentation.mp4", stored_hash)
"""

import hashlib
from pathlib import Path

CHUNK_SIZE = 65_536  # 64 KB — efficient for large files


def compute_sha256(file_path: str) -> str:
    """Return the hex SHA-256 digest of *file_path*, reading in chunks.

    Reading in fixed-size chunks keeps memory usage bounded regardless of
    file size.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Return the hex SHA-256 digest of raw *data* bytes."""
    return hashlib.sha256(data).hexdigest()


def verify_file(file_path: str, expected_hash: str) -> bool:
    """Compare *file_path*'s SHA-256 against *expected_hash*.

    Prints a human-readable result and returns ``True`` when the hashes
    match, ``False`` when they differ (indicating possible corruption or
    tampering).
    """
    actual_hash = compute_sha256(file_path)
    print(f"[Warden] Expected: {expected_hash}")
    print(f"[Warden] Actual:   {actual_hash}")

    if actual_hash == expected_hash:
        print("[Warden] \u2705 Integrity VERIFIED")
        return True
    else:
        print("[Warden] \u274c Integrity FAILURE \u2014 possible corruption")
        return False


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "Video_Evidence_Documentation.mp4"

    # First run: generate and store this hash in your ledger
    generated_hash = compute_sha256(path)
    print(f"[Warden] Generated SHA-256: {generated_hash}")

    # Later: verify against a stored hash passed as the second argument
    if len(sys.argv) > 2:
        verify_file(path, sys.argv[2])
