"""
TrustWipe Forensic Recovery
---------------------------
Cryptographic hashing utilities for forensic evidence.

The SHA-256 hash produced by this module is intended to establish
and verify the cryptographic identity of an evidence file.

Important:
    The hash is calculated using a streaming read so that large
    evidence files do not need to be loaded into memory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final


DEFAULT_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MiB


class HashingError(Exception):
    """Base exception for hashing-related failures."""


class EvidenceNotFoundError(HashingError):
    """Raised when the evidence file does not exist."""


class EvidenceTypeError(HashingError):
    """Raised when the supplied path is not a regular file."""


class EvidenceAccessError(HashingError):
    """Raised when the evidence file cannot be read."""


def sha256_file(
    path: Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Calculate the SHA-256 digest of a file.

    The file is read incrementally to support very large forensic
    evidence files.

    Args:
        path:
            Path to the evidence file.

        chunk_size:
            Number of bytes read per iteration.
            Defaults to 1 MiB.

    Returns:
        Lowercase hexadecimal SHA-256 digest.

    Raises:
        EvidenceNotFoundError:
            If the evidence file does not exist.

        EvidenceTypeError:
            If the path does not point to a regular file.

        EvidenceAccessError:
            If the file cannot be opened or read.

        ValueError:
            If chunk_size is invalid.
    """

    if not isinstance(path, Path):
        path = Path(path)

    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    if not path.exists():
        raise EvidenceNotFoundError(
            f"Evidence file does not exist: {path}"
        )

    # Do not silently hash directories, devices, sockets, etc.
    if not path.is_file():
        raise EvidenceTypeError(
            f"Evidence path is not a regular file: {path}"
        )

    digest = hashlib.sha256()

    try:
        with path.open("rb") as evidence_file:
            while True:
                chunk = evidence_file.read(chunk_size)

                if not chunk:
                    break

                digest.update(chunk)

    except (OSError, PermissionError) as exc:
        raise EvidenceAccessError(
            f"Unable to read evidence file '{path}': {exc}"
        ) from exc

    return digest.hexdigest()
	