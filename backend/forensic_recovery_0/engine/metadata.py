"""
TrustWipe Forensic Recovery
---------------------------
Filesystem and basic metadata extraction.

This module extracts metadata that is available from the filesystem
without attempting to interpret the contents of the file.

IMPORTANT:
    `mime_guess` is only a filename-based MIME type guess. It must
    never be treated as proof of the actual file format.

Content-based identification should be performed separately by
the forensic scanner/carving/validation pipeline.
"""

from __future__ import annotations

import mimetypes
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class MetadataError(Exception):
    """Base exception for metadata extraction failures."""


class MetadataNotFoundError(MetadataError):
    """Raised when the target file does not exist."""


class MetadataTypeError(MetadataError):
    """Raised when the target is not a regular file."""


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """
    Basic filesystem metadata for an evidence file.

    Timestamps are represented in UTC ISO-8601 format.
    """

    name: str
    path: str
    size: int
    suffix: str
    mime_guess: str | None
    created_utc: str | None
    modified_utc: str | None
    accessed_utc: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return asdict(self)


def _utc_timestamp(timestamp: float) -> str:
    """
    Convert a filesystem timestamp into an ISO-8601 UTC timestamp.
    """

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).isoformat()


def basic_metadata(path: Path) -> dict[str, Any]:
    """
    Extract basic filesystem metadata from a file.

    Args:
        path:
            Path to the evidence file.

    Returns:
        Dictionary containing filesystem metadata.

    Raises:
        MetadataNotFoundError:
            If the file does not exist.

        MetadataTypeError:
            If the path is not a regular file.

        MetadataError:
            If filesystem metadata cannot be read.
    """

    if not isinstance(path, Path):
        path = Path(path)

    if not path.exists():
        raise MetadataNotFoundError(
            f"Evidence file does not exist: {path}"
        )

    if path.is_symlink():
        raise MetadataTypeError(
            f"Symbolic links are not accepted: {path}"
        )

    if not path.is_file():
        raise MetadataTypeError(
            f"Path is not a regular file: {path}"
        )

    try:
        resolved_path = path.resolve(strict=True)
        stat = resolved_path.stat()

    except OSError as exc:
        raise MetadataError(
            f"Unable to read metadata for '{path}': {exc}"
        ) from exc

    mime, _ = mimetypes.guess_type(
        resolved_path.name,
        strict=False,
    )

    metadata = FileMetadata(
        name=resolved_path.name,
        path=str(resolved_path),
        size=stat.st_size,
        mime_guess=mime,
        suffix=resolved_path.suffix.lower(),
        created_utc=_utc_timestamp(stat.st_ctime),
        modified_utc=_utc_timestamp(stat.st_mtime),
        accessed_utc=_utc_timestamp(stat.st_atime),
    )

    return metadata.to_dict()
	