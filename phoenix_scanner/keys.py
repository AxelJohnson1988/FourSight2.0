"""Ed25519 key ceremony utilities with safe storage practices."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logger = logging.getLogger(__name__)

_PRIV_SUFFIX = ".priv"
_PUB_SUFFIX = ".pub"


class OverwriteBlockedError(FileExistsError):
    """Raised when the key ceremony would overwrite an existing key file."""


def perform_key_ceremony(
    base_name: str = "signing_key",
    *,
    directory: Path = Path("."),
    overwrite: bool = False,
) -> tuple[Path, Path]:
    """Generate an Ed25519 keypair and write raw bytes to disk.

    Parameters
    ----------
    base_name:
        Stem for the output files (e.g. ``"signing_key"`` →
        ``signing_key.priv`` / ``signing_key.pub``).
    directory:
        Target directory (created if it does not exist).
    overwrite:
        Set to ``True`` to allow overwriting existing files.  Default is
        ``False`` (safe default).

    Returns
    -------
    tuple[Path, Path]
        Paths to the ``(private_key_file, public_key_file)``.

    Notes
    -----
    - The *private* key file is written with mode ``0o600``; it is the
      caller's responsibility to keep it offline and never upload it.
    - Private key bytes are **never** logged.
    - Store the private key as hex in the ``PHOENIX_PRIVATE_KEY_HEX``
      environment variable for signing operations; do not re-read it from
      disk in automated pipelines.
    """
    directory.mkdir(parents=True, exist_ok=True)
    priv_path = directory / (base_name + _PRIV_SUFFIX)
    pub_path = directory / (base_name + _PUB_SUFFIX)

    if priv_path.exists() and not overwrite:
        raise OverwriteBlockedError(
            f"{priv_path} already exists. OVERWRITE BLOCKED. "
            "Pass overwrite=True only if you are certain."
        )

    private_key = Ed25519PrivateKey.generate()
    pub_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_raw = private_key.private_bytes_raw()  # type: ignore[attr-defined]

    # Write private key with restricted permissions
    priv_path.write_bytes(priv_raw)
    os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    pub_path.write_bytes(pub_raw)

    logger.info("Key ceremony complete. Public key: %s", pub_raw.hex())
    logger.info("Private key written to: %s (chmod 600)", priv_path)
    logger.warning(
        "IMPORTANT: Move %s to offline storage immediately. "
        "Never commit it to version control.",
        priv_path,
    )
    return priv_path, pub_path


def load_public_key_hex(pub_path: Path) -> str:
    """Read raw public key bytes and return as hex string."""
    raw = pub_path.read_bytes()
    if len(raw) != 32:
        raise ValueError(
            f"Expected 32 raw bytes for Ed25519 public key; got {len(raw)}"
        )
    return raw.hex()
