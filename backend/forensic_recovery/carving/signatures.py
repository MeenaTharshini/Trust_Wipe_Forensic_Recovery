from typing import Dict, List, Optional, Any

class FileSignature:
    def __init__(self, name: str, extension: str, header: bytes, footer: Optional[bytes] = None, max_size: int = 20 * 1024 * 1024, category: str = "General"):
        self.name = name
        self.extension = extension
        self.header = header
        self.footer = footer
        self.max_size = max_size
        self.category = category

# Standard Forensic Magic Byte Definitions
DEFAULT_SIGNATURES: List[FileSignature] = [
    FileSignature(
        name="JPEG Image",
        extension="jpg",
        header=b"\xFF\xD8\xFF",
        footer=b"\xFF\xD9",
        max_size=15 * 1024 * 1024,
        category="Images"
    ),
    FileSignature(
        name="PNG Image",
        extension="png",
        header=b"\x89PNG\x0D\x0A\x1A\x0A",
        footer=b"IEND\xAE\x42\x60\x82",
        max_size=15 * 1024 * 1024,
        category="Images"
    ),
    FileSignature(
        name="PDF Document",
        extension="pdf",
        header=b"%PDF-",
        footer=b"%%EOF",
        max_size=30 * 1024 * 1024,
        category="Documents"
    ),
    FileSignature(
        name="ZIP / Office Document",
        extension="zip",
        header=b"PK\x03\x04",
        footer=b"PK\x05\x06",
        max_size=50 * 1024 * 1024,
        category="Archives"
    ),
    FileSignature(
        name="SQLite Database",
        extension="sqlite",
        header=b"SQLite format 3\x00",
        footer=None,
        max_size=50 * 1024 * 1024,
        category="Databases"
    ),
    FileSignature(
        name="MP4 Video",
        extension="mp4",
        header=b"\x00\x00\x00\x18ftyp",
        footer=None,
        max_size=100 * 1024 * 1024,
        category="Media"
    ),
    FileSignature(
        name="Windows Executable",
        extension="exe",
        header=b"MZ",
        footer=None,
        max_size=30 * 1024 * 1024,
        category="Executables"
    )
]

def get_signature_by_name(name: str) -> Optional[FileSignature]:
    for sig in DEFAULT_SIGNATURES:
        if sig.name.lower() == name.lower():
            return sig
    return None
