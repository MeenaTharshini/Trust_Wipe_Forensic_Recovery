"""
TrustWipe Forensic Recovery
---------------------------
Range-based forensic file carving.

The evidence image is never modified.

Recovered artifacts are written separately from the
original evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .signatures import Signature
from .validators import validate_artifact


class CarvingError(Exception):
    pass


class CarvingOutputError(CarvingError):
    pass


class CarvingLimitError(CarvingError):
    pass


@dataclass(frozen=True, slots=True)
class CarvedArtifact:

    artifact_id: str
    type: str
    extension: str

    offset: int
    size: int

    output: str

    sha256: str

    status: str
    confidence: int

    validation_message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _prepare_output_directory(
    output_dir: Path,
) -> Path:

    output_dir = Path(output_dir)

    try:
        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )
    except OSError as exc:
        raise CarvingOutputError(
            f"Unable to create output directory: {exc}"
        ) from exc

    if not output_dir.is_dir():
        raise CarvingOutputError(
            "Carving output path is not a directory."
        )

    return output_dir.resolve()


def _artifact_filename(
    index: int,
    signature: Signature,
) -> str:

    return (
        f"carved_{index:05d}"
        f"{signature.extension}"
    )


def _find_footer_in_file(
    evidence_path: Path,
    start: int,
    signature: Signature,
    evidence_size: int,
    chunk_size: int = 4 * 1024 * 1024,
) -> int | None:

    if signature.footer is None:
        return None

    search_start = start + len(signature.header)

    search_end = min(
        start + signature.max_size,
        evidence_size,
    )

    if search_start >= search_end:
        return None

    footer = signature.footer

    overlap = len(footer) - 1

    position = search_start

    previous = b""

    with evidence_path.open("rb") as evidence:

        evidence.seek(search_start)

        while position < search_end:

            to_read = min(
                chunk_size,
                search_end - position,
            )

            chunk = evidence.read(to_read)

            if not chunk:
                break

            data = previous + chunk

            found = data.find(footer)

            if found != -1:

                absolute = (
                    position
                    - len(previous)
                    + found
                )

                return absolute + len(footer)

            previous = (
                data[-overlap:]
                if overlap > 0
                else b""
            )

            position += len(chunk)

    return None


def _copy_range(
    evidence_path: Path,
    output_path: Path,
    start: int,
    end: int,
    chunk_size: int = 4 * 1024 * 1024,
) -> str:

    if end <= start:
        raise CarvingError(
            "Invalid carving range."
        )

    size = end - start

    sha256 = hashlib.sha256()

    with (
        evidence_path.open("rb") as source,
        output_path.open("xb") as destination,
    ):

        source.seek(start)

        remaining = size

        while remaining > 0:

            chunk = source.read(
                min(chunk_size, remaining)
            )

            if not chunk:
                raise CarvingError(
                    "Unexpected end of evidence while carving."
                )

            destination.write(chunk)

            sha256.update(chunk)

            remaining -= len(chunk)

    return sha256.hexdigest()


def carve_ranges(
    evidence_path: Path,
    hits: list[tuple[int, Signature]],
    output_dir: Path,
    *,
    max_artifacts: int = 10000,
) -> list[dict[str, Any]]:

    evidence_path = Path(evidence_path)

    output_dir = _prepare_output_directory(
        output_dir
    )

    if max_artifacts <= 0:
        raise ValueError(
            "max_artifacts must be greater than zero"
        )

    if not evidence_path.exists():
        raise CarvingError(
            f"Evidence does not exist: {evidence_path}"
        )

    evidence_size = evidence_path.stat().st_size

    results: list[dict[str, Any]] = []

    # Remove duplicate detection hits.
    unique_hits: dict[
        tuple[int, str],
        tuple[int, Signature],
    ] = {}

    for offset, signature in hits:

        unique_hits[
            (
                offset,
                signature.name,
            )
        ] = (
            offset,
            signature,
        )

    ordered_hits = sorted(
        unique_hits.values(),
        key=lambda item: (
            item[0],
            item[1].name,
        ),
    )

    for offset, signature in ordered_hits:

        if len(results) >= max_artifacts:
            break

        if offset < 0:
            continue

        if offset >= evidence_size:
            continue

        header_end = (
            offset
            + len(signature.header)
        )

        if header_end > evidence_size:
            continue

        # Determine end using format footer if available.
        end = _find_footer_in_file(
            evidence_path,
            offset,
            signature,
            evidence_size,
        )

        if end is None:

            # If no footer exists, do NOT consume the
            # entire evidence image.

            end = min(
                offset + signature.max_size,
                evidence_size,
            )

            # If another signature occurs before this
            # maximum range, stop at that candidate.
            for next_offset, _ in ordered_hits:

                if next_offset > offset:

                    end = min(
                        end,
                        next_offset,
                    )

                    break

        if end <= offset:
            continue

        size = end - offset

        if size > signature.max_size:
            raise CarvingLimitError(
                f"Artifact exceeds maximum size: "
                f"{signature.name}"
            )

        filename = _artifact_filename(
            len(results),
            signature,
        )

        output_path = (
            output_dir / filename
        )

        # Carve bytes from the evidence.
        digest = _copy_range(
            evidence_path,
            output_path,
            offset,
            end,
        )

        validation = validate_artifact(
            output_path,
            signature.name,
        )

        artifact = CarvedArtifact(
            artifact_id=(
                f"CARVED-"
                f"{len(results) + 1:05d}"
            ),
            type=signature.name,
            extension=signature.extension,
            offset=offset,
            size=size,
            output=str(output_path),
            sha256=digest,
            status=str(
                validation["status"]
            ),
            confidence=int(
                validation["confidence"]
            ),
            validation_message=str(
                validation["message"]
            ),
        )

        results.append(
            artifact.to_dict()
        )

    return results


def carve_bytes(
    data: bytes,
    output_dir: Path,
    *,
    overwrite: bool = False,
    max_artifacts: int | None = None,
) -> list[dict[str, Any]]:
    """
    Compatibility function for existing tests/code.

    This retains the original API.
    """

    from .signatures import find_signatures

    if not isinstance(
        data,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError(
            "data must be bytes-like"
        )

    output_dir = _prepare_output_directory(
        output_dir
    )

    raw = bytes(data)

    hits = find_signatures(raw)

    if not hits:
        return []

    results: list[dict[str, Any]] = []

    for offset, signature in hits:

        if (
            max_artifacts is not None
            and len(results) >= max_artifacts
        ):
            break

        maximum_end = min(
            offset + signature.max_size,
            len(raw),
        )

        end = None

        if signature.footer:

            footer_position = raw.find(
                signature.footer,
                offset + len(signature.header),
                maximum_end,
            )

            if footer_position != -1:
                end = (
                    footer_position
                    + len(signature.footer)
                )

        if end is None:

            next_positions = [
                p
                for p, _ in hits
                if p > offset
            ]

            end = min(
                [maximum_end]
                + next_positions
            )

        if end <= offset:
            continue

        filename = _artifact_filename(
            len(results),
            signature,
        )

        output_path = output_dir / filename

        if output_path.exists():

            if not overwrite:
                raise CarvingError(
                    f"Artifact already exists: "
                    f"{output_path}"
                )

            output_path.unlink()

        output_path.write_bytes(
            raw[offset:end]
        )

        digest = hashlib.sha256(
            raw[offset:end]
        ).hexdigest()

        validation = validate_artifact(
            output_path,
            signature.name,
        )

        artifact = CarvedArtifact(
            artifact_id=(
                f"CARVED-"
                f"{len(results) + 1:05d}"
            ),
            type=signature.name,
            extension=signature.extension,
            offset=offset,
            size=end - offset,
            output=str(output_path),
            sha256=digest,
            status=str(
                validation["status"]
            ),
            confidence=int(
                validation["confidence"]
            ),
            validation_message=str(
                validation["message"]
            ),
        )

        results.append(
            artifact.to_dict()
        )

    return results