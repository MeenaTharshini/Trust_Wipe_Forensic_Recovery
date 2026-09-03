from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class FileSignature:
    """
    Defines a file format signature used by the forensic carver.

    Attributes:
        name: Human-readable file type.
        extension: Recovered file extension.
        header: Magic bytes identifying the beginning of the file.
        footer: Optional magic bytes identifying the end of the file.
        max_size: Maximum number of bytes to carve.
        category: Logical artifact category.
        mime_type: MIME type of the artifact.
        min_size: Minimum acceptable carved size.
    """

    name: str
    extension: str
    header: bytes
    footer: Optional[bytes] = None
    max_size: int = 20 * 1024 * 1024
    category: str = "General"
    mime_type: str = "application/octet-stream"
    min_size: int = 8


# ----------------------------------------------------------------------
# STANDARD FORENSIC FILE SIGNATURES
# ----------------------------------------------------------------------

DEFAULT_SIGNATURES: List[FileSignature] = [

    # --------------------------------------------------------------
    # IMAGES
    # --------------------------------------------------------------

    FileSignature(
        name="JPEG Image",
        extension="jpg",
        header=b"\xFF\xD8\xFF",
        footer=b"\xFF\xD9",
        max_size=15 * 1024 * 1024,
        min_size=20,
        category="Images",
        mime_type="image/jpeg",
    ),

    FileSignature(
        name="PNG Image",
        extension="png",
        header=b"\x89PNG\r\n\x1a\n",
        footer=b"IEND\xAE\x42\x60\x82",
        max_size=15 * 1024 * 1024,
        min_size=33,
        category="Images",
        mime_type="image/png",
    ),

    FileSignature(
        name="GIF Image",
        extension="gif",
        header=b"GIF8",
        footer=b"\x3B",
        max_size=15 * 1024 * 1024,
        min_size=20,
        category="Images",
        mime_type="image/gif",
    ),

    FileSignature(
        name="BMP Image",
        extension="bmp",
        header=b"BM",
        footer=None,
        max_size=20 * 1024 * 1024,
        min_size=54,
        category="Images",
        mime_type="image/bmp",
    ),

    # --------------------------------------------------------------
    # DOCUMENTS
    # --------------------------------------------------------------

    FileSignature(
        name="PDF Document",
        extension="pdf",
        header=b"%PDF-",
        footer=b"%%EOF",
        max_size=50 * 1024 * 1024,
        min_size=20,
        category="Documents",
        mime_type="application/pdf",
    ),

    # --------------------------------------------------------------
    # ZIP / OFFICE
    # --------------------------------------------------------------

    FileSignature(
        name="ZIP Archive",
        extension="zip",
        header=b"PK\x03\x04",
        footer=b"PK\x05\x06",
        max_size=100 * 1024 * 1024,
        min_size=22,
        category="Archives",
        mime_type="application/zip",
    ),

    # ZIP64 / empty archive variants
    FileSignature(
        name="ZIP Archive Empty",
        extension="zip",
        header=b"PK\x05\x06",
        footer=None,
        max_size=100 * 1024 * 1024,
        min_size=22,
        category="Archives",
        mime_type="application/zip",
    ),

    # --------------------------------------------------------------
    # DATABASES
    # --------------------------------------------------------------

    FileSignature(
        name="SQLite Database",
        extension="sqlite",
        header=b"SQLite format 3\x00",
        footer=None,
        max_size=500 * 1024 * 1024,
        min_size=100,
        category="Databases",
        mime_type="application/vnd.sqlite3",
    ),

    # --------------------------------------------------------------
    # AUDIO
    # --------------------------------------------------------------

    FileSignature(
        name="MP3 Audio",
        extension="mp3",
        header=b"ID3",
        footer=None,
        max_size=100 * 1024 * 1024,
        min_size=10,
        category="Audio",
        mime_type="audio/mpeg",
    ),

    # MPEG audio frame
    FileSignature(
        name="MPEG Audio",
        extension="mp3",
        header=b"\xFF\xFB",
        footer=None,
        max_size=100 * 1024 * 1024,
        min_size=4,
        category="Audio",
        mime_type="audio/mpeg",
    ),

    # --------------------------------------------------------------
    # VIDEO / MEDIA
    # --------------------------------------------------------------

    # MP4/MOV files use an ISO Base Media File Format structure.
    # The header can contain a variable 4-byte box size, so this
    # signature is intentionally broad.
    FileSignature(
        name="MP4 Video",
        extension="mp4",
        header=b"ftyp",
        footer=None,
        max_size=500 * 1024 * 1024,
        min_size=16,
        category="Media",
        mime_type="video/mp4",
    ),

    # --------------------------------------------------------------
    # EXECUTABLES
    # --------------------------------------------------------------

    FileSignature(
        name="Windows PE Executable",
        extension="exe",
        header=b"MZ",
        footer=None,
        max_size=100 * 1024 * 1024,
        min_size=64,
        category="Executables",
        mime_type="application/vnd.microsoft.portable-executable",
    ),

    # --------------------------------------------------------------
    # RTF
    # --------------------------------------------------------------

    FileSignature(
        name="RTF Document",
        extension="rtf",
        header=b"{\\rtf",
        footer=b"}",
        max_size=50 * 1024 * 1024,
        min_size=10,
        category="Documents",
        mime_type="application/rtf",
    ),
]


def get_signature_by_name(
    name: str,
) -> Optional[FileSignature]:
    """
    Returns a signature by its human-readable name.
    """

    if not name:
        return None

    normalized = name.strip().lower()

    for signature in DEFAULT_SIGNATURES:
        if signature.name.lower() == normalized:
            return signature

    return None


def get_signatures_by_category(
    category: str,
) -> List[FileSignature]:
    """
    Returns all signatures belonging to a category.
    """

    if not category:
        return []

    normalized = category.strip().lower()

    return [
        signature
        for signature in DEFAULT_SIGNATURES
        if signature.category.lower() == normalized
    ]