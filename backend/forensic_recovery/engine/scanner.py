"""
TrustWipe Forensic Recovery
---------------------------

Streaming forensic scanner.

The evidence image is processed incrementally.

The complete evidence image is never loaded into RAM.

Pipeline:

    Evidence
        ↓
    Streaming signature discovery
        ↓
    Deduplication
        ↓
    Range carving
        ↓
    Format validation
        ↓
    SHA-256 artifact hashing
        ↓
    Scan result
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

from ..carving.carver import carve_ranges
from ..carving.signatures import SIGNATURES, Signature


DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024


class ScannerError(Exception):
    pass


class ScannerInputError(ScannerError):
    pass


class ScannerReadError(ScannerError):
    pass


class ScannerLimitError(ScannerError):
    pass


@dataclass(frozen=True, slots=True)
class ScanResult:

    evidence_path: str
    evidence_size: int

    chunk_size: int
    overlap_size: int

    chunks_scanned: int
    bytes_scanned: int

    signatures_detected: int
    candidate_ranges: int

    artifacts_carved: int
    artifacts_validated: int

    artifacts: list[dict[str, Any]]

    status: str = "COMPLETED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validate_image(
    image_path: Path,
) -> Path:

    image_path = Path(image_path)

    if not image_path.exists():
        raise ScannerInputError(
            f"Evidence image does not exist: {image_path}"
        )

    if image_path.is_symlink():
        raise ScannerInputError(
            "Symbolic links are not accepted as evidence."
        )

    if not image_path.is_file():
        raise ScannerInputError(
            "Evidence image is not a regular file."
        )

    try:
        return image_path.resolve(
            strict=True
        )

    except OSError as exc:
        raise ScannerInputError(
            f"Unable to resolve evidence image: {exc}"
        ) from exc


def _validate_output_directory(
    output_dir: Path,
) -> Path:

    output_dir = Path(output_dir)

    try:
        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    except OSError as exc:
        raise ScannerInputError(
            (
                "Unable to create recovery output "
                f"directory '{output_dir}': {exc}"
            )
        ) from exc

    if not output_dir.is_dir():
        raise ScannerInputError(
            "Recovery output path is not a directory."
        )

    try:
        return output_dir.resolve(
            strict=True
        )

    except OSError as exc:
        raise ScannerInputError(
            (
                "Unable to resolve recovery output "
                f"directory '{output_dir}': {exc}"
            )
        ) from exc


def _calculate_overlap(
    signatures: tuple[Signature, ...],
) -> int:

    if not signatures:
        return 1

    longest_header = max(
        len(signature.header)
        for signature in signatures
    )

    return max(
        longest_header - 1,
        1,
    )


def _read_chunks(
    image_path: Path,
    chunk_size: int,
    overlap_size: int,
) -> Iterator[
    tuple[int, bytes, int]
]:
    """
    Yield:

        absolute_offset,
        buffer,
        actual_chunk_bytes

    The buffer may contain overlap bytes from the previous chunk.
    """

    absolute_offset = 0
    overlap = b""

    try:

        with image_path.open("rb") as evidence:

            while True:

                chunk = evidence.read(
                    chunk_size
                )

                if not chunk:
                    break

                if overlap:

                    buffer = (
                        overlap
                        + chunk
                    )

                    buffer_offset = (
                        absolute_offset
                        - len(overlap)
                    )

                else:

                    buffer = chunk
                    buffer_offset = absolute_offset

                yield (
                    buffer_offset,
                    buffer,
                    len(chunk),
                )

                if overlap_size > 0:

                    overlap = (
                        buffer[-overlap_size:]
                    )

                else:
                    overlap = b""

                absolute_offset += len(chunk)

    except OSError as exc:

        raise ScannerReadError(
            (
                f"Unable to read evidence image "
                f"'{image_path}': {exc}"
            )
        ) from exc


def _find_chunk_signatures(
    buffer: bytes,
    buffer_offset: int,
    signatures: tuple[Signature, ...],
) -> list[
    tuple[int, Signature]
]:

    results: list[
        tuple[int, Signature]
    ] = []

    if not buffer:
        return results

    for signature in signatures:

        header = signature.header

        if not header:
            continue

        search_start = 0

        while search_start < len(buffer):

            position = buffer.find(
                header,
                search_start,
            )

            if position == -1:
                break

            absolute_position = (
                buffer_offset
                + position
            )

            results.append(
                (
                    absolute_position,
                    signature,
                )
            )

            search_start = position + 1

    return results


def _deduplicate_hits(
    detected: list[
        tuple[int, Signature]
    ],
) -> list[
    tuple[int, Signature]
]:

    unique: dict[
        tuple[int, str, str],
        tuple[int, Signature],
    ] = {}

    for offset, signature in detected:

        key = (
            offset,
            signature.name,
            signature.extension,
        )

        unique[key] = (
            offset,
            signature,
        )

    return sorted(
        unique.values(),
        key=lambda item: (
            item[0],
            item[1].name,
            item[1].extension,
        ),
    )


def scan_image(
    image_path: Path,
    output_dir: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    *,
    signatures: tuple[
        Signature, ...
    ] = SIGNATURES,
) -> dict[str, Any]:

    if chunk_size <= 0:
        raise ScannerLimitError(
            "chunk_size must be greater than zero."
        )

    if not signatures:
        raise ScannerLimitError(
            "At least one file signature is required."
        )

    overlap_size = _calculate_overlap(
        signatures
    )

    if overlap_size >= chunk_size:
        raise ScannerLimitError(
            (
                "chunk_size must be larger than "
                "signature overlap size."
            )
        )

    evidence_path = _validate_image(
        image_path
    )

    recovery_output = (
        _validate_output_directory(
            output_dir
        )
    )

    try:
        evidence_size = (
            evidence_path.stat().st_size
        )

    except OSError as exc:
        raise ScannerInputError(
            f"Unable to determine evidence size: {exc}"
        ) from exc

    if evidence_size == 0:

        return ScanResult(
            evidence_path=str(
                evidence_path
            ),
            evidence_size=0,

            chunk_size=chunk_size,
            overlap_size=overlap_size,

            chunks_scanned=0,
            bytes_scanned=0,

            signatures_detected=0,
            candidate_ranges=0,

            artifacts_carved=0,
            artifacts_validated=0,

            artifacts=[],

            status="COMPLETED",
        ).to_dict()

    detected: list[
        tuple[int, Signature]
    ] = []

    chunks_scanned = 0
    bytes_scanned = 0

    # ================================================================
    # STREAMING DISCOVERY
    # ================================================================

    for (
        buffer_offset,
        buffer,
        actual_chunk_size,
    ) in _read_chunks(
        evidence_path,
        chunk_size,
        overlap_size,
    ):

        chunks_scanned += 1
        bytes_scanned += actual_chunk_size

        detected.extend(
            _find_chunk_signatures(
                buffer,
                buffer_offset,
                signatures,
            )
        )

    # ================================================================
    # DEDUPLICATION
    # ================================================================

    ordered_hits = _deduplicate_hits(
        detected
    )

    # ================================================================
    # CARVING
    # ================================================================

    artifacts: list[
        dict[str, Any]
    ] = []

    if ordered_hits:

        try:

            artifacts = carve_ranges(
                evidence_path=evidence_path,
                hits=ordered_hits,
                output_dir=recovery_output,
                max_artifacts=10000,
            )

        except Exception as exc:

            raise ScannerError(
                (
                    "Forensic artifact carving failed: "
                    f"{exc}"
                )
            ) from exc

    # ================================================================
    # VALIDATION COUNT
    # ================================================================

    artifacts_validated = sum(
        1
        for artifact in artifacts
        if artifact.get("status") == "VALID"
    )

    # ================================================================
    # RESULT
    # ================================================================

    return ScanResult(
        evidence_path=str(
            evidence_path
        ),

        evidence_size=evidence_size,

        chunk_size=chunk_size,
        overlap_size=overlap_size,

        chunks_scanned=chunks_scanned,
        bytes_scanned=bytes_scanned,

        signatures_detected=len(
            ordered_hits
        ),

        candidate_ranges=len(
            ordered_hits
        ),

        artifacts_carved=len(
            artifacts
        ),

        artifacts_validated=artifacts_validated,

        artifacts=artifacts,

        status="COMPLETED",
    ).to_dict()


__all__ = [
    "ScannerError",
    "ScannerInputError",
    "ScannerReadError",
    "ScannerLimitError",
    "ScanResult",
    "scan_image",
]//
test_carver.py:
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from carving.carver import carve_bytes


class TestCarver(unittest.TestCase):

    def test_jpeg_carving(self):
        data = (
            b"xxxx"
            + bytes.fromhex("FFD8FF")
            + b"TEST-IMAGE-DATA"
            + bytes.fromhex("FFD9")
            + b"yyyy"
        )

        with TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "out"

            result = carve_bytes(data, output_dir)

            self.assertEqual(len(result), 1)
            self.assertTrue(
                (output_dir / "carved_00000.jpg").exists()
            )


if __name__ == "__main__":
    unittest.main()