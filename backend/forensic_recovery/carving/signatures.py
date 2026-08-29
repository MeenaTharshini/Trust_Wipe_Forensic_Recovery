"""
TrustWipe Forensic Recovery
---------------------------

File signature definitions and discovery.

IMPORTANT:
    Signature detection only identifies candidates.

    DETECTED != VALID

The forensic pipeline is:

    DETECTED
        ↓
    CARVED
        ↓
    VALIDATED
        ↓
    ACCEPTED / REJECTED

The evidence image is never modified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Signature:
    """
    Definition of a recoverable file format.
    """

    name: str
    extension: str
    header: bytes
    footer: bytes | None
    max_size: int

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Signature name cannot be empty.")

        if not self.extension.startswith("."):
            raise ValueError(
                f"Invalid extension for {self.name}: {self.extension}"
            )

        if not self.header:
            raise ValueError(
                f"Header cannot be empty for {self.name}."
            )

        if self.footer == b"":
            raise ValueError(
                f"Footer must be None or non-empty for {self.name}."
            )

        if self.max_size <= 0:
            raise ValueError(
                f"max_size must be greater than zero for {self.name}."
            )


# ============================================================================
# IMAGE FORMATS
# ============================================================================

JPEG_SIGNATURE: Final[Signature] = Signature(
    name="JPEG",
    extension=".jpg",
    header=b"\xFF\xD8\xFF",
    footer=b"\xFF\xD9",
    max_size=50 * 1024 * 1024,
)


PNG_SIGNATURE: Final[Signature] = Signature(
    name="PNG",
    extension=".png",
    header=b"\x89PNG\r\n\x1a\n",
    footer=b"\x49\x45\x4E\x44\xAE\x42\x60\x82",
    max_size=100 * 1024 * 1024,
)


GIF_SIGNATURE: Final[Signature] = Signature(
    name="GIF",
    extension=".gif",
    header=b"GIF8",
    footer=b"\x00\x3B",
    max_size=50 * 1024 * 1024,
)


BMP_SIGNATURE: Final[Signature] = Signature(
    name="BMP",
    extension=".bmp",
    header=b"BM",
    footer=None,
    max_size=100 * 1024 * 1024,
)


# ============================================================================
# DOCUMENTS
# ============================================================================

PDF_SIGNATURE: Final[Signature] = Signature(
    name="PDF",
    extension=".pdf",
    header=b"%PDF-",
    footer=b"%%EOF",
    max_size=200 * 1024 * 1024,
)


RTF_SIGNATURE: Final[Signature] = Signature(
    name="RTF",
    extension=".rtf",
    header=b"{\\rtf",
    footer=None,
    max_size=50 * 1024 * 1024,
)


# ============================================================================
# ARCHIVES
# ============================================================================

ZIP_SIGNATURE: Final[Signature] = Signature(
    name="ZIP",
    extension=".zip",
    header=b"PK\x03\x04",
    footer=b"PK\x05\x06",
    max_size=500 * 1024 * 1024,
)


ZIP_EMPTY_SIGNATURE: Final[Signature] = Signature(
    name="ZIP",
    extension=".zip",
    header=b"PK\x05\x06",
    footer=None,
    max_size=500 * 1024 * 1024,
)


RAR_SIGNATURE: Final[Signature] = Signature(
    name="RAR",
    extension=".rar",
    header=b"Rar!\x1A\x07\x00",
    footer=None,
    max_size=500 * 1024 * 1024,
)


RAR5_SIGNATURE: Final[Signature] = Signature(
    name="RAR5",
    extension=".rar",
    header=b"Rar!\x1A\x07\x01\x00",
    footer=None,
    max_size=500 * 1024 * 1024,
)


SEVEN_Z_SIGNATURE: Final[Signature] = Signature(
    name="7-Zip",
    extension=".7z",
    header=b"\x37\x7A\xBC\xAF\x27\x1C",
    footer=None,
    max_size=500 * 1024 * 1024,
)


# ============================================================================
# MEDIA
# ============================================================================

MP3_ID3_SIGNATURE: Final[Signature] = Signature(
    name="MP3",
    extension=".mp3",
    header=b"ID3",
    footer=None,
    max_size=200 * 1024 * 1024,
)


# IMPORTANT:
# Do NOT use b"\xFF" as a generic MP3 signature.
#
# A random binary file can contain thousands of FF bytes.
# That produces catastrophic false positives.
#
# We therefore intentionally omit generic MPEG-frame discovery here.


WAV_SIGNATURE: Final[Signature] = Signature(
    name="WAV",
    extension=".wav",
    header=b"RIFF",
    footer=None,
    max_size=500 * 1024 * 1024,
)


WEBP_SIGNATURE: Final[Signature] = Signature(
    name="WEBP",
    extension=".webp",
    header=b"RIFF",
    footer=None,
    max_size=100 * 1024 * 1024,
)


MP4_SIGNATURE: Final[Signature] = Signature(
    name="MP4",
    extension=".mp4",
    header=b"ftyp",
    footer=None,
    max_size=2 * 1024 * 1024 * 1024,
)


# ============================================================================
# DATABASE / EXECUTABLE
# ============================================================================

SQLITE_SIGNATURE: Final[Signature] = Signature(
    name="SQLite",
    extension=".sqlite",
    header=b"SQLite format 3\x00",
    footer=None,
    max_size=500 * 1024 * 1024,
)


PE_SIGNATURE: Final[Signature] = Signature(
    name="Windows PE",
    extension=".exe",
    header=b"MZ",
    footer=None,
    max_size=500 * 1024 * 1024,
)


ELF_SIGNATURE: Final[Signature] = Signature(
    name="ELF",
    extension=".elf",
    header=b"\x7FELF",
    footer=None,
    max_size=500 * 1024 * 1024,
)


# ============================================================================
# MASTER TABLE
# ============================================================================

SIGNATURES: Final[tuple[Signature, ...]] = (
    JPEG_SIGNATURE,
    PNG_SIGNATURE,
    GIF_SIGNATURE,
    BMP_SIGNATURE,

    PDF_SIGNATURE,
    RTF_SIGNATURE,

    ZIP_SIGNATURE,
    ZIP_EMPTY_SIGNATURE,
    RAR_SIGNATURE,
    RAR5_SIGNATURE,
    SEVEN_Z_SIGNATURE,

    MP3_ID3_SIGNATURE,

    WAV_SIGNATURE,
    WEBP_SIGNATURE,
    MP4_SIGNATURE,

    SQLITE_SIGNATURE,
    PE_SIGNATURE,
    ELF_SIGNATURE,
)


def find_signatures(
    data: bytes,
    signatures: tuple[Signature, ...] = SIGNATURES,
) -> list[tuple[int, Signature]]:
    """
    Find candidate signatures in a byte buffer.

    This function performs detection only.

    Detection does NOT prove that an artifact is valid.
    """

    if not isinstance(
        data,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("data must be bytes-like.")

    raw = bytes(data)

    if not raw:
        return []

    hits: list[tuple[int, Signature]] = []

    for signature in signatures:

        search_start = 0

        while search_start < len(raw):

            position = raw.find(
                signature.header,
                search_start,
            )

            if position == -1:
                break

            hits.append(
                (
                    position,
                    signature,
                )
            )

            # Advance by one so overlapping signatures are
            # not accidentally skipped.
            search_start = position + 1

    return sorted(
        hits,
        key=lambda item: (
            item[0],
            item[1].name,
            item[1].extension,
        ),
    )


__all__ = [
    "Signature",

    "JPEG_SIGNATURE",
    "PNG_SIGNATURE",
    "GIF_SIGNATURE",
    "BMP_SIGNATURE",

    "PDF_SIGNATURE",
    "RTF_SIGNATURE",

    "ZIP_SIGNATURE",
    "ZIP_EMPTY_SIGNATURE",
    "RAR_SIGNATURE",
    "RAR5_SIGNATURE",
    "SEVEN_Z_SIGNATURE",

    "MP3_ID3_SIGNATURE",

    "WAV_SIGNATURE",
    "WEBP_SIGNATURE",
    "MP4_SIGNATURE",

    "SQLITE_SIGNATURE",
    "PE_SIGNATURE",
    "ELF_SIGNATURE",

    "SIGNATURES",
    "find_signatures",
]
