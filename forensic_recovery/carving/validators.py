"""
TrustWipe Forensic Recovery
---------------------------

Artifact validation.

A carved artifact is accepted only when it passes
format-specific structural validation.

Validation statuses:

    VALID
    INVALID
    UNKNOWN
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any


def _result(
    status: str,
    confidence: int,
    message: str,
) -> dict[str, Any]:
    return {
        "status": status,
        "confidence": confidence,
        "message": message,
    }


def _validate_jpeg(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if len(data) < 4:
        return _result(
            "INVALID",
            0,
            "JPEG is too small.",
        )

    if not data.startswith(b"\xFF\xD8\xFF"):
        return _result(
            "INVALID",
            0,
            "Invalid JPEG header.",
        )

    if not data.endswith(b"\xFF\xD9"):
        return _result(
            "INVALID",
            20,
            "JPEG end marker is missing.",
        )

    return _result(
        "VALID",
        100,
        "JPEG header and end marker are valid.",
    )


def _validate_png(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    png_header = b"\x89PNG\r\n\x1a\n"
    png_footer = b"\x49\x45\x4E\x44\xAE\x42\x60\x82"

    if not data.startswith(png_header):
        return _result(
            "INVALID",
            0,
            "Invalid PNG header.",
        )

    if len(data) < 33:
        return _result(
            "INVALID",
            20,
            "PNG is too small for a valid IHDR structure.",
        )

    if not data.endswith(png_footer):
        return _result(
            "INVALID",
            30,
            "PNG IEND marker is missing.",
        )

    # Verify IHDR chunk.
    try:
        ihdr_length = struct.unpack(
            ">I",
            data[8:12],
        )[0]

        ihdr_type = data[12:16]

        if ihdr_length != 13 or ihdr_type != b"IHDR":
            return _result(
                "INVALID",
                40,
                "PNG IHDR chunk is invalid.",
            )

    except struct.error:
        return _result(
            "INVALID",
            20,
            "PNG IHDR structure could not be parsed.",
        )

    return _result(
        "VALID",
        100,
        "PNG signature, IHDR and IEND are valid.",
    )


def _validate_gif(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if not (
        data.startswith(b"GIF87a")
        or data.startswith(b"GIF89a")
    ):
        return _result(
            "INVALID",
            0,
            "Invalid GIF header.",
        )

    if not data.endswith(b"\x00\x3B"):
        return _result(
            "INVALID",
            30,
            "GIF trailer is missing.",
        )

    if len(data) < 14:
        return _result(
            "INVALID",
            30,
            "GIF is too small.",
        )

    return _result(
        "VALID",
        100,
        "GIF header and trailer are valid.",
    )


def _validate_bmp(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if len(data) < 14:
        return _result(
            "INVALID",
            0,
            "BMP is too small.",
        )

    if data[:2] != b"BM":
        return _result(
            "INVALID",
            0,
            "Invalid BMP signature.",
        )

    declared_size = struct.unpack(
        "<I",
        data[2:6],
    )[0]

    if declared_size != len(data):
        return _result(
            "INVALID",
            60,
            (
                "BMP header is present but declared file size "
                f"({declared_size}) does not match carved size "
                f"({len(data)})."
            ),
        )

    return _result(
        "VALID",
        100,
        "BMP signature and declared file size are valid.",
    )


def _validate_pdf(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if not data.startswith(b"%PDF-"):
        return _result(
            "INVALID",
            0,
            "Invalid PDF header.",
        )

    if b"%%EOF" not in data:
        return _result(
            "INVALID",
            30,
            "PDF EOF marker is missing.",
        )

    return _result(
        "VALID",
        100,
        "PDF header and EOF marker are present.",
    )


def _validate_rtf(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if not data.startswith(b"{\\rtf"):
        return _result(
            "INVALID",
            0,
            "Invalid RTF header.",
        )

    if not data.rstrip().endswith(b"}"):
        return _result(
            "INVALID",
            50,
            "RTF closing brace is missing.",
        )

    return _result(
        "VALID",
        90,
        "RTF structure appears valid.",
    )


def _validate_zip(path: Path) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            bad_file = archive.testzip()

            if bad_file is not None:
                return _result(
                    "INVALID",
                    50,
                    f"ZIP CRC validation failed for {bad_file}.",
                )

            archive.infolist()

        return _result(
            "VALID",
            100,
            "ZIP central directory and CRC validation succeeded.",
        )

    except zipfile.BadZipFile as exc:
        return _result(
            "INVALID",
            0,
            f"Invalid ZIP archive: {exc}",
        )

    except OSError as exc:
        return _result(
            "INVALID",
            0,
            f"Unable to read ZIP archive: {exc}",
        )


def _validate_rar(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if not (
        data.startswith(b"Rar!\x1A\x07\x00")
        or data.startswith(b"Rar!\x1A\x07\x01\x00")
    ):
        return _result(
            "INVALID",
            0,
            "Invalid RAR signature.",
        )

    return _result(
        "UNKNOWN",
        60,
        (
            "RAR signature is valid, but complete archive "
            "validation requires a RAR parser."
        ),
    )


def _validate_7z(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    header = b"\x37\x7A\xBC\xAF\x27\x1C"

    if not data.startswith(header):
        return _result(
            "INVALID",
            0,
            "Invalid 7-Zip signature.",
        )

    return _result(
        "UNKNOWN",
        60,
        (
            "7-Zip signature is valid, but complete archive "
            "validation requires 7-Zip structural parsing."
        ),
    )


def _validate_mp3(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if not data.startswith(b"ID3"):
        return _result(
            "INVALID",
            0,
            "MP3 ID3 header is missing.",
        )

    if len(data) < 10:
        return _result(
            "INVALID",
            20,
            "MP3 ID3 header is incomplete.",
        )

    return _result(
        "VALID",
        90,
        "MP3 ID3 header is structurally present.",
    )


def _validate_riff(
    path: Path,
    expected_type: bytes,
) -> dict[str, Any]:
    data = path.read_bytes()

    if len(data) < 12:
        return _result(
            "INVALID",
            0,
            "RIFF file is too small.",
        )

    if data[:4] != b"RIFF":
        return _result(
            "INVALID",
            0,
            "RIFF header is missing.",
        )

    if data[8:12] != expected_type:
        return _result(
            "INVALID",
            30,
            (
                "RIFF container type does not match expected "
                f"{expected_type!r}."
            ),
        )

    declared_size = struct.unpack(
        "<I",
        data[4:8],
    )[0]

    expected_total = declared_size + 8

    if expected_total > len(data):
        return _result(
            "INVALID",
            50,
            "RIFF declared size exceeds carved artifact size.",
        )

    return _result(
        "VALID",
        100,
        "RIFF container and format identifier are valid.",
    )


def _validate_wav(path: Path) -> dict[str, Any]:
    return _validate_riff(
        path,
        b"WAVE",
    )


def _validate_webp(path: Path) -> dict[str, Any]:
    return _validate_riff(
        path,
        b"WEBP",
    )


def _validate_mp4(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if len(data) < 12:
        return _result(
            "INVALID",
            0,
            "MP4 candidate is too small.",
        )

    # ftyp box normally begins at offset 4.
    if data[4:8] != b"ftyp":
        return _result(
            "INVALID",
            0,
            "MP4 ftyp box is missing.",
        )

    box_size = struct.unpack(
        ">I",
        data[:4],
    )[0]

    if box_size < 8:
        return _result(
            "INVALID",
            20,
            "Invalid MP4 ftyp box size.",
        )

    if box_size > len(data):
        return _result(
            "INVALID",
            40,
            "MP4 ftyp box exceeds carved artifact size.",
        )

    return _result(
        "VALID",
        90,
        "MP4 ftyp box is structurally valid.",
    )


def _validate_sqlite(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    header = b"SQLite format 3\x00"

    if not data.startswith(header):
        return _result(
            "INVALID",
            0,
            "Invalid SQLite header.",
        )

    if len(data) < 100:
        return _result(
            "INVALID",
            40,
            "SQLite database header is incomplete.",
        )

    page_size = int.from_bytes(
        data[16:18],
        "big",
    )

    if page_size == 1:
        page_size = 65536

    if page_size < 512 or page_size > 32768:
        if page_size != 65536:
            return _result(
                "INVALID",
                50,
                "SQLite page size is invalid.",
            )

    return _result(
        "VALID",
        90,
        "SQLite database header is structurally valid.",
    )


def _validate_pe(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if not data.startswith(b"MZ"):
        return _result(
            "INVALID",
            0,
            "Invalid PE/DOS header.",
        )

    if len(data) < 64:
        return _result(
            "INVALID",
            30,
            "PE/DOS header is incomplete.",
        )

    pe_offset = int.from_bytes(
        data[60:64],
        "little",
    )

    if pe_offset + 4 > len(data):
        return _result(
            "INVALID",
            40,
            "PE header offset exceeds carved artifact.",
        )

    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return _result(
            "INVALID",
            40,
            "PE signature is missing.",
        )

    return _result(
        "VALID",
        100,
        "DOS MZ header and PE signature are valid.",
    )


def _validate_elf(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    if not data.startswith(b"\x7FELF"):
        return _result(
            "INVALID",
            0,
            "Invalid ELF signature.",
        )

    if len(data) < 16:
        return _result(
            "INVALID",
            30,
            "ELF header is incomplete.",
        )

    elf_class = data[4]

    if elf_class not in (1, 2):
        return _result(
            "INVALID",
            50,
            "Invalid ELF class.",
        )

    endian = data[5]

    if endian not in (1, 2):
        return _result(
            "INVALID",
            50,
            "Invalid ELF endianness.",
        )

    return _result(
        "VALID",
        100,
        "ELF header is structurally valid.",
    )


def validate_artifact(
    path: Path,
    signature_name: str,
) -> dict[str, Any]:
    """
    Validate a carved artifact according to its detected format.
    """

    path = Path(path)

    if not path.exists():
        return _result(
            "INVALID",
            0,
            "Recovered artifact does not exist.",
        )

    validators = {
        "JPEG": _validate_jpeg,
        "PNG": _validate_png,
        "GIF": _validate_gif,
        "BMP": _validate_bmp,
        "PDF": _validate_pdf,
        "RTF": _validate_rtf,
        "ZIP": _validate_zip,
        "RAR": _validate_rar,
        "RAR5": _validate_rar,
        "7-Zip": _validate_7z,
        "MP3": _validate_mp3,
        "WAV": _validate_wav,
        "WEBP": _validate_webp,
        "MP4": _validate_mp4,
        "SQLite": _validate_sqlite,
        "Windows PE": _validate_pe,
        "ELF": _validate_elf,
    }

    validator = validators.get(signature_name)

    if validator is None:
        return _result(
            "UNKNOWN",
            0,
            f"No validator is registered for {signature_name}.",
        )

    try:
        return validator(path)

    except (OSError, ValueError, struct.error) as exc:
        return _result(
            "INVALID",
            0,
            f"Validation failed: {exc}",
        )


__all__ = [
    "validate_artifact",
]

