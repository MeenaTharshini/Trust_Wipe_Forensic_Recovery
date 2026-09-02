"""
TrustWipe Forensic Recovery
---------------------------
Evidence identification and acquisition metadata.

This module creates the cryptographic acquisition baseline for
forensic evidence.

The acquisition hash must be preserved and used later for
integrity verification.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from .hashing import sha256_file


HASH_ALGORITHM: Final[str] = "SHA-256"
EVIDENCE_SCHEMA_VERSION: Final[str] = "1.0"


class EvidenceAcquisitionError(Exception):
    """Base exception for evidence acquisition failures."""


class EvidenceNotFoundError(EvidenceAcquisitionError):
    """Raised when the evidence file does not exist."""


class EvidenceTypeError(EvidenceAcquisitionError):
    """Raised when the evidence path is not a regular file."""


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """
    Immutable forensic evidence acquisition record.

    This object represents the state of the evidence at the
    moment it was acquired by TrustWipe.
    """

    path: str
    size: int
    sha256: str
    acquired_utc: str
    hash_algorithm: str = HASH_ALGORITHM
    schema_version: str = EVIDENCE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the evidence record into a JSON-serializable dictionary.
        """
        return asdict(self)


def _validate_evidence_path(path: Path) -> Path:
    """
    Validate and normalize an evidence path.

    Symlinks are rejected deliberately because forensic acquisition
    should identify the actual evidence object rather than silently
    follow a potentially changing link.
    """

    if not isinstance(path, Path):
        path = Path(path)

    if not path.exists():
        raise EvidenceNotFoundError(
            f"Evidence file does not exist: {path}"
        )

    if path.is_symlink():
        raise EvidenceTypeError(
            f"Symbolic links are not accepted as evidence: {path}"
        )

    if not path.is_file():
        raise EvidenceTypeError(
            f"Evidence path is not a regular file: {path}"
        )

    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise EvidenceAcquisitionError(
            f"Unable to resolve evidence path '{path}': {exc}"
        ) from exc


def identify(path: Path) -> EvidenceItem:
    """
    Acquire an evidence identification record.

    The acquisition process:

        1. Validate evidence path.
        2. Resolve the absolute path.
        3. Record initial file size.
        4. Calculate SHA-256.
        5. Record acquisition timestamp.
        6. Re-check file size.
        7. Reject the acquisition if the file changed
           while it was being hashed.

    Args:
        path:
            Path to the evidence file.

    Returns:
        EvidenceItem containing the acquisition baseline.

    Raises:
        EvidenceAcquisitionError:
            If the evidence cannot be safely acquired.
    """

    evidence_path = _validate_evidence_path(path)

    try:
        initial_stat = evidence_path.stat()
        initial_size = initial_stat.st_size

        acquired_utc = datetime.now(timezone.utc).isoformat()

        digest = sha256_file(evidence_path)

        final_stat = evidence_path.stat()
        final_size = final_stat.st_size

    except OSError as exc:
        raise EvidenceAcquisitionError(
            f"Unable to acquire evidence '{evidence_path}': {exc}"
        ) from exc

    # Important forensic safeguard:
    # If the file changed during hashing, the acquisition baseline
    # cannot safely represent a stable evidence object.
    if initial_size != final_size:
        raise EvidenceAcquisitionError(
            "Evidence changed during acquisition: "
            f"size changed from {initial_size} to {final_size} bytes"
        )

    return EvidenceItem(
        path=str(evidence_path),
        size=final_size,
        sha256=digest,
        acquired_utc=acquired_utc,
        hash_algorithm=HASH_ALGORITHM,
        schema_version=EVIDENCE_SCHEMA_VERSION,
    )