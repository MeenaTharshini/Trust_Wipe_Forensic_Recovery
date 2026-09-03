import math
import os
import struct
import uuid
import zipfile
import zlib

from io import BytesIO
from typing import Any, Dict, List, Optional, Set, Tuple

from .signatures import DEFAULT_SIGNATURES, FileSignature
from ..acquisition.hashing import CryptographicHasher


class FileCarver:
    """
    Production-oriented forensic signature-based file carver.

    Processing pipeline:

        Evidence
            ↓
        Signature detection
            ↓
        Candidate range detection
            ↓
        Boundary determination
            ↓
        Structural validation
            ↓
        Artifact recovery
            ↓
        Cryptographic hashing
            ↓
        Artifact registration

    Important forensic properties:

    - Original evidence is opened read-only.
    - Original evidence is never modified.
    - Artifact source offsets are preserved.
    - Validation is format-aware where supported.
    - Entropy is only a supporting indicator.
    - Unknown formats are not automatically marked VALIDATED.
    - Invalid candidates are not registered as recovered artifacts.
    """

    DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
    DEFAULT_OVERLAP = 128 * 1024

    # Safety limits
    MAX_PNG_CHUNKS = 100_000
    MAX_MP4_BOXES = 100_000
    MAX_PE_SECTIONS = 96
    MAX_MP3_SCAN = 1024 * 1024

    VALIDATED = "VALIDATED"
    PARTIAL = "PARTIAL"
    REJECTED = "REJECTED"

    def __init__(
        self,
        output_dir: str,
        signatures: Optional[List[FileSignature]] = None,
    ):
        self.output_dir = os.path.abspath(output_dir)

        self.signatures = (
            signatures
            if signatures is not None
            else DEFAULT_SIGNATURES
        )

        os.makedirs(
            self.output_dir,
            exist_ok=True
        )

        # Prevent duplicate artifacts from being written
        # repeatedly because of overlapping chunks.
        self._written_keys: Set[str] = set()

    # ==========================================================
    # ENTROPY
    # ==========================================================

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy.

        Entropy is NOT a validity test.
        It is only an analytical indicator.
        """

        if not data:
            return 0.0

        counts = [0] * 256

        for byte in data:
            counts[byte] += 1

        length = len(data)

        entropy = 0.0

        for count in counts:
            if count == 0:
                continue

            probability = count / length

            entropy -= (
                probability
                * math.log2(probability)
            )

        return round(entropy, 3)

    @staticmethod
    def _classify_entropy(entropy: float) -> str:

        if entropy < 1.0:
            return "Very Low"

        if entropy < 3.0:
            return "Low"

        if entropy < 6.5:
            return "Normal"

        if entropy < 7.8:
            return "High"

        return "Very High"

    # ==========================================================
    # BASIC SIGNATURE CHECKS
    # ==========================================================

    @staticmethod
    def _header_matches(
        data: bytes,
        signature: FileSignature,
    ) -> bool:

        return data.startswith(signature.header)

    @staticmethod
    def _footer_matches(
        data: bytes,
        signature: FileSignature,
    ) -> bool:

        if not signature.footer:
            return False

        return data.endswith(signature.footer)

    # ==========================================================
    # FORMAT VALIDATION
    # ==========================================================

    def _validate_format(
        self,
        data: bytes,
        signature: FileSignature,
    ) -> Tuple[str, str]:

        if len(data) < signature.min_size:
            return (
                self.REJECTED,
                "Candidate is smaller than the minimum format size",
            )

        if not self._header_matches(
            data,
            signature,
        ):
            return (
                self.REJECTED,
                "File signature/header mismatch",
            )

        name = str(
            signature.name
        ).strip().upper()

        # ------------------------------------------------------
        # JPEG
        # ------------------------------------------------------

        if name == "JPEG":

            valid, reason = self._validate_jpeg(data)

            return (
                self.VALIDATED if valid else self.REJECTED,
                reason,
            )

        # ------------------------------------------------------
        # PNG
        # ------------------------------------------------------

        if name == "PNG":

            valid, reason = self._validate_png(data)

            if valid:
                return (
                    self.VALIDATED,
                    reason,
                )

            # Correctly identified PNG with incomplete
            # end marker is considered PARTIAL.
            if "IEND" in reason or "incomplete" in reason.lower():
                return (
                    self.PARTIAL,
                    reason,
                )

            return (
                self.REJECTED,
                reason,
            )

        # ------------------------------------------------------
        # PDF
        # ------------------------------------------------------

        if name == "PDF":

            return self._validate_pdf(data)

        # ------------------------------------------------------
        # ZIP
        # ------------------------------------------------------

        if name == "ZIP":

            valid, reason = self._validate_zip(data)

            return (
                self.VALIDATED if valid else self.REJECTED,
                reason,
            )

        # ------------------------------------------------------
        # GIF
        # ------------------------------------------------------

        if name == "GIF":

            valid, reason = self._validate_gif(data)

            if valid:
                return (
                    self.VALIDATED,
                    reason,
                )

            return (
                self.PARTIAL if "trailer" in reason.lower()
                else self.REJECTED,
                reason,
            )

        # ------------------------------------------------------
        # BMP
        # ------------------------------------------------------

        if name == "BMP":

            valid, reason = self._validate_bmp(data)

            return (
                self.VALIDATED if valid else self.REJECTED,
                reason,
            )

        # ------------------------------------------------------
        # SQLITE
        # ------------------------------------------------------

        if name in (
            "SQLITE",
            "SQLITE DATABASE",
        ):

            valid, reason = self._validate_sqlite(data)

            return (
                self.VALIDATED if valid else self.REJECTED,
                reason,
            )

        # ------------------------------------------------------
        # MP4 / ISO-BMFF
        # ------------------------------------------------------

        if name in (
            "MP4",
            "MP4/ISO-BMFF",
            "ISO-BMFF",
        ):

            valid, reason = self._validate_mp4(data)

            return (
                self.VALIDATED if valid else self.PARTIAL,
                reason,
            )

        # ------------------------------------------------------
        # PE / EXE
        # ------------------------------------------------------

        if name in (
            "EXE",
            "WINDOWS PE",
            "PE",
        ):

            valid, reason = self._validate_pe(data)

            return (
                self.VALIDATED if valid else self.REJECTED,
                reason,
            )

        # ------------------------------------------------------
        # MP3
        # ------------------------------------------------------

        if name == "MP3":

            valid, reason = self._validate_mp3(data)

            return (
                self.VALIDATED if valid else self.REJECTED,
                reason,
            )

        # ------------------------------------------------------
        # RTF
        # ------------------------------------------------------

        if name == "RTF":

            if data.startswith(b"{\\rtf"):
                return (
                    self.VALIDATED,
                    "RTF header verified",
                )

            return (
                self.REJECTED,
                "Invalid RTF header",
            )

        # ------------------------------------------------------
        # Generic signature
        # ------------------------------------------------------

        if signature.footer:

            if self._footer_matches(
                data,
                signature,
            ):
                return (
                    self.VALIDATED,
                    "Header and footer signatures verified",
                )

            return (
                self.PARTIAL,
                "Expected footer signature not found",
            )

        return (
            self.PARTIAL,
            "Header detected but no format-specific validator exists",
        )

    # ==========================================================
    # JPEG VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_jpeg(
        data: bytes,
    ) -> Tuple[bool, str]:

        if len(data) < 4:
            return (
                False,
                "JPEG candidate is too small",
            )

        if not data.startswith(b"\xFF\xD8\xFF"):
            return (
                False,
                "Invalid JPEG SOI/header",
            )

        if not data.endswith(b"\xFF\xD9"):
            return (
                False,
                "JPEG end-of-image marker not found",
            )

        # Search for a Start Of Frame marker.
        pos = 2
        saw_sof = False

        while pos + 4 <= len(data) - 2:

            if data[pos] != 0xFF:
                pos += 1
                continue

            while pos < len(data) and data[pos] == 0xFF:
                pos += 1

            if pos >= len(data):
                break

            marker = data[pos]

            # EOI
            if marker == 0xD9:
                break

            # Standalone markers
            if marker in (
                0x01,
                *range(0xD0, 0xD8),
            ):
                pos += 1
                continue

            if pos + 2 > len(data):
                return (
                    False,
                    "Incomplete JPEG segment length",
                )

            segment_length = struct.unpack(
                ">H",
                data[pos + 1:pos + 3],
            )[0]

            if segment_length < 2:
                return (
                    False,
                    "Invalid JPEG segment length",
                )

            segment_end = pos + 1 + segment_length

            if segment_end > len(data):
                return (
                    False,
                    "JPEG segment extends beyond recovered data",
                )

            # SOF markers
            if marker in (
                0xC0,
                0xC1,
                0xC2,
                0xC3,
                0xC5,
                0xC6,
                0xC7,
                0xC9,
                0xCA,
                0xCB,
                0xCD,
                0xCE,
                0xCF,
            ):
                if segment_length >= 7:
                    height = struct.unpack(
                        ">H",
                        data[pos + 4:pos + 6],
                    )[0]

                    width = struct.unpack(
                        ">H",
                        data[pos + 6:pos + 8],
                    )[0]

                    if width == 0 or height == 0:
                        return (
                            False,
                            "JPEG image dimensions are invalid",
                        )

                    saw_sof = True

            pos = segment_end

        if not saw_sof:
            return (
                False,
                "JPEG SOF image structure not detected",
            )

        return (
            True,
            "JPEG SOI, image structure and EOI verified",
        )

    # ==========================================================
    # PNG VALIDATION
    # ==========================================================

    @classmethod
    def _validate_png(
        cls,
        data: bytes,
    ) -> Tuple[bool, str]:

        signature = b"\x89PNG\r\n\x1a\n"

        if not data.startswith(signature):
            return (
                False,
                "Invalid PNG signature",
            )

        if len(data) < 33:
            return (
                False,
                "Incomplete PNG header",
            )

        position = 8
        saw_ihdr = False
        saw_iend = False
        chunk_count = 0

        while position + 12 <= len(data):

            if chunk_count >= cls.MAX_PNG_CHUNKS:
                return (
                    False,
                    "PNG contains an abnormally large number of chunks",
                )

            length = struct.unpack(
                ">I",
                data[position:position + 4],
            )[0]

            chunk_type = data[
                position + 4:position + 8
            ]

            chunk_start = position + 8
            chunk_end = chunk_start + length
            crc_end = chunk_end + 4

            if crc_end > len(data):
                return (
                    False,
                    "Incomplete PNG chunk data",
                )

            # PNG chunk type must contain alphabetic ASCII.
            if len(chunk_type) != 4 or not all(
                (65 <= b <= 90) or (97 <= b <= 122)
                for b in chunk_type
            ):
                return (
                    False,
                    "Invalid PNG chunk type",
                )

            chunk_data = data[
                chunk_start:chunk_end
            ]

            stored_crc = struct.unpack(
                ">I",
                data[chunk_end:crc_end],
            )[0]

            calculated_crc = (
                zlib.crc32(
                    chunk_type + chunk_data
                )
                & 0xFFFFFFFF
            )

            if calculated_crc != stored_crc:
                return (
                    False,
                    "PNG chunk CRC validation failed",
                )

            if chunk_type == b"IHDR":

                if saw_ihdr:
                    return (
                        False,
                        "PNG contains multiple IHDR chunks",
                    )

                if length != 13:
                    return (
                        False,
                        "PNG IHDR chunk has invalid length",
                    )

                width = struct.unpack(
                    ">I",
                    chunk_data[0:4],
                )[0]

                height = struct.unpack(
                    ">I",
                    chunk_data[4:8],
                )[0]

                if width == 0 or height == 0:
                    return (
                        False,
                        "PNG dimensions are invalid",
                    )

                saw_ihdr = True

            elif chunk_type == b"IEND":

                if length != 0:
                    return (
                        False,
                        "PNG IEND chunk must have zero data length",
                    )

                saw_iend = True

                # IEND should be the final chunk.
                if crc_end != len(data):
                    return (
                        False,
                        "PNG contains data after IEND",
                    )

                break

            position = crc_end
            chunk_count += 1

        if not saw_ihdr:
            return (
                False,
                "PNG IHDR chunk not found",
            )

        if not saw_iend:
            return (
                False,
                "PNG IEND marker not found",
            )

        return (
            True,
            "PNG signature, IHDR, chunk CRCs and IEND verified",
        )

    # ==========================================================
    # PDF VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_pdf(
        data: bytes,
    ) -> Tuple[str, str]:

        if not data.startswith(b"%PDF-"):
            return (
                FileCarver.REJECTED,
                "Invalid PDF header",
            )

        if len(data) < 8:
            return (
                FileCarver.PARTIAL,
                "Incomplete PDF header",
            )

        eof_position = data.rfind(b"%%EOF")

        if eof_position == -1:
            return (
                FileCarver.PARTIAL,
                "PDF EOF marker not found",
            )

        # PDF may contain binary bytes. We deliberately do not
        # claim full PDF semantic validation here.
        return (
            FileCarver.VALIDATED,
            "PDF header and EOF marker verified",
        )

    # ==========================================================
    # ZIP VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_zip(
        data: bytes,
    ) -> Tuple[bool, str]:

        if len(data) < 22:
            return (
                False,
                "ZIP candidate is too small",
            )

        if not (
            data.startswith(b"PK\x03\x04")
            or data.startswith(b"PK\x05\x06")
            or data.startswith(b"PK\x07\x08")
        ):
            return (
                False,
                "Invalid ZIP signature",
            )

        try:
            with zipfile.ZipFile(
                BytesIO(data),
                "r",
            ) as archive:

                bad_member = archive.testzip()

                if bad_member is not None:
                    return (
                        False,
                        f"ZIP member failed CRC check: {bad_member}",
                    )

                # getmembers() forces central directory parsing.
                archive.infolist()

                return (
                    True,
                    "ZIP central directory and member CRCs verified",
                )

        except (
            zipfile.BadZipFile,
            OSError,
            RuntimeError,
        ):
            return (
                False,
                "ZIP structure could not be parsed",
            )

    # ==========================================================
    # GIF VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_gif(
        data: bytes,
    ) -> Tuple[bool, str]:

        if not (
            data.startswith(b"GIF87a")
            or data.startswith(b"GIF89a")
        ):
            return (
                False,
                "Invalid GIF header",
            )

        if len(data) < 13:
            return (
                False,
                "GIF header is incomplete",
            )

        width = struct.unpack(
            "<H",
            data[6:8],
        )[0]

        height = struct.unpack(
            "<H",
            data[8:10],
        )[0]

        if width == 0 or height == 0:
            return (
                False,
                "GIF dimensions are invalid",
            )

        if not data.endswith(b"\x3B"):
            return (
                False,
                "GIF trailer not found",
            )

        return (
            True,
            "GIF header, dimensions and trailer verified",
        )

    # ==========================================================
    # BMP VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_bmp(
        data: bytes,
    ) -> Tuple[bool, str]:

        if len(data) < 54:
            return (
                False,
                "BMP candidate is too small",
            )

        if data[:2] != b"BM":
            return (
                False,
                "Invalid BMP signature",
            )

        try:
            declared_size = struct.unpack(
                "<I",
                data[2:6],
            )[0]

            pixel_offset = struct.unpack(
                "<I",
                data[10:14],
            )[0]

            dib_size = struct.unpack(
                "<I",
                data[14:18],
            )[0]

            width = struct.unpack(
                "<i",
                data[18:22],
            )[0]

            height = struct.unpack(
                "<i",
                data[22:26],
            )[0]

            bits_per_pixel = struct.unpack(
                "<H",
                data[28:30],
            )[0]

        except struct.error:
            return (
                False,
                "BMP structural header could not be parsed",
            )

        if dib_size < 12:
            return (
                False,
                "Unsupported or invalid BMP DIB header",
            )

        if width == 0 or height == 0:
            return (
                False,
                "BMP dimensions are invalid",
            )

        if pixel_offset < 14 + dib_size:
            return (
                False,
                "BMP pixel data offset is invalid",
            )

        if pixel_offset >= len(data):
            return (
                False,
                "BMP pixel data lies outside recovered artifact",
            )

        if bits_per_pixel == 0:
            return (
                False,
                "BMP bits-per-pixel value is invalid",
            )

        if declared_size > 0 and declared_size > len(data):
            return (
                False,
                "BMP declared file size exceeds recovered size",
            )

        return (
            True,
            "BMP file header and DIB structure verified",
        )

    # ==========================================================
    # SQLITE VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_sqlite(
        data: bytes,
    ) -> Tuple[bool, str]:

        if len(data) < 100:
            return (
                False,
                "SQLite header is incomplete",
            )

        if not data.startswith(
            b"SQLite format 3\x00"
        ):
            return (
                False,
                "Invalid SQLite signature",
            )

        try:
            page_size = struct.unpack(
                ">H",
                data[16:18],
            )[0]

            page_count = struct.unpack(
                ">I",
                data[28:32],
            )[0]

        except struct.error:
            return (
                False,
                "SQLite header could not be parsed",
            )

        if page_size == 1:
            page_size = 65536

        if page_size < 512 or page_size > 65536:
            return (
                False,
                "Invalid SQLite page size",
            )

        if page_size & (page_size - 1):
            return (
                False,
                "SQLite page size is not a power of two",
            )

        if page_count == 0:
            return (
                False,
                "SQLite page count is zero",
            )

        expected_size = page_size * page_count

        if expected_size > len(data):
            return (
                False,
                "Recovered SQLite artifact is smaller than declared database size",
            )

        return (
            True,
            "SQLite signature, page size and database size verified",
        )

    # ==========================================================
    # MP4 / ISO-BMFF VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_mp4(
        data: bytes,
    ) -> Tuple[bool, str]:

        if len(data) < 16:
            return (
                False,
                "MP4 candidate is too small",
            )

        if data[4:8] != b"ftyp":
            return (
                False,
                "MP4 ftyp box not found",
            )

        position = 0
        box_count = 0
        saw_ftyp = False

        while position + 8 <= len(data):

            if box_count >= FileCarver.MAX_MP4_BOXES:
                return (
                    False,
                    "MP4 contains an abnormally large number of boxes",
                )

            size = struct.unpack(
                ">I",
                data[position:position + 4],
            )[0]

            box_type = data[
                position + 4:position + 8
            ]

            header_size = 8

            if size == 1:

                if position + 16 > len(data):
                    return (
                        False,
                        "Incomplete extended MP4 box size",
                    )

                size = struct.unpack(
                    ">Q",
                    data[position + 8:position + 16],
                )[0]

                header_size = 16

            elif size == 0:

                # Box extends to EOF.
                size = len(data) - position

            if size < header_size:
                return (
                    False,
                    "Invalid MP4 box size",
                )

            box_end = position + size

            if box_end > len(data):
                return (
                    False,
                    "MP4 box extends beyond recovered data",
                )

            if box_type == b"ftyp":
                saw_ftyp = True

            position = box_end
            box_count += 1

            # size=0 means this box consumes EOF.
            if (
                struct.unpack(
                    ">I",
                    data[
                        position - size:
                        position - size + 4
                    ],
                )[0] == 0
            ):
                break

        if not saw_ftyp:
            return (
                False,
                "MP4 ftyp box was not validated",
            )

        if position != len(data):
            return (
                False,
                "Trailing incomplete MP4 data detected",
            )

        return (
            True,
            "ISO-BMFF box structure and ftyp box verified",
        )

    # ==========================================================
    # PE VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_pe(
        data: bytes,
    ) -> Tuple[bool, str]:

        if len(data) < 64:
            return (
                False,
                "PE candidate is too small",
            )

        if data[:2] != b"MZ":
            return (
                False,
                "DOS MZ header not found",
            )

        try:
            pe_offset = struct.unpack(
                "<I",
                data[60:64],
            )[0]

        except struct.error:
            return (
                False,
                "Invalid PE header offset",
            )

        if (
            pe_offset < 64
            or pe_offset + 24 > len(data)
        ):
            return (
                False,
                "PE header lies outside recovered data",
            )

        if data[
            pe_offset:
            pe_offset + 4
        ] != b"PE\x00\x00":
            return (
                False,
                "PE signature not found",
            )

        try:
            machine = struct.unpack(
                "<H",
                data[pe_offset + 4:pe_offset + 6],
            )[0]

            sections = struct.unpack(
                "<H",
                data[pe_offset + 6:pe_offset + 8],
            )[0]

            optional_size = struct.unpack(
                "<H",
                data[pe_offset + 20:pe_offset + 22],
            )[0]

        except struct.error:
            return (
                False,
                "Invalid PE COFF header",
            )

        if sections == 0 or sections > FileCarver.MAX_PE_SECTIONS:
            return (
                False,
                "Invalid PE section count",
            )

        if optional_size == 0:
            return (
                False,
                "PE optional header is missing",
            )

        valid_machines = {
            0x014C,
            0x8664,
            0x01C0,
            0xAA64,
        }

        if machine not in valid_machines:
            return (
                False,
                "Unknown PE machine architecture",
            )

        optional_start = pe_offset + 24
        optional_end = optional_start + optional_size

        if optional_end > len(data):
            return (
                False,
                "PE optional header exceeds recovered data",
            )

        if optional_size >= 2:
            magic = struct.unpack(
                "<H",
                data[
                    optional_start:
                    optional_start + 2
                ],
            )[0]

            if magic not in (
                0x10B,
                0x20B,
                0x107,
            ):
                return (
                    False,
                    "Invalid PE optional-header magic",
                )

        return (
            True,
            "MZ header, PE signature, COFF and optional header verified",
        )

    # ==========================================================
    # MP3 VALIDATION
    # ==========================================================

    @staticmethod
    def _validate_mp3(
        data: bytes,
    ) -> Tuple[bool, str]:

        if len(data) < 4:
            return (
                False,
                "MP3 candidate is too small",
            )

        scan_start = 0

        # Skip ID3v2 header when present.
        if data.startswith(b"ID3"):

            if len(data) < 10:
                return (
                    False,
                    "Incomplete ID3v2 header",
                )

            flags = data[5]

            if flags & 0x0F:
                return (
                    False,
                    "Invalid ID3v2 flags",
                )

            tag_size = (
                ((data[6] & 0x7F) << 21)
                | ((data[7] & 0x7F) << 14)
                | ((data[8] & 0x7F) << 7)
                | (data[9] & 0x7F)
            )

            scan_start = 10 + tag_size

            if scan_start >= len(data):
                return (
                    False,
                    "MP3 contains ID3 metadata but no MPEG audio frame",
                )

        limit = min(
            len(data) - 1,
            FileCarver.MAX_MP3_SCAN,
        )

        for index in range(
            scan_start,
            limit,
        ):

            first = data[index]
            second = data[index + 1]

            if first != 0xFF:
                continue

            if (second & 0xE0) != 0xE0:
                continue

            version = (
                second >> 3
            ) & 0x03

            layer = (
                second >> 1
            ) & 0x03

            if version == 1:
                continue

            if layer == 0:
                continue

            if index + 4 > len(data):
                continue

            third = data[index + 2]

            bitrate_index = (
                third >> 4
            ) & 0x0F

            sample_rate_index = (
                third >> 2
            ) & 0x03

            if bitrate_index in (
                0,
                15,
            ):
                continue

            if sample_rate_index == 3:
                continue

            return (
                True,
                "ID3/MPEG audio frame structure detected",
            )

        return (
            False,
            "Valid MPEG audio frame was not detected",
        )

    # ==========================================================
    # BOUNDARY DETECTION
    # ==========================================================

    def _find_carve_end(
        self,
        buffer: bytes,
        header_position: int,
        signature: FileSignature,
    ) -> Optional[int]:

        header_end = (
            header_position
            + len(signature.header)
        )

        max_end = min(
            len(buffer),
            header_position
            + signature.max_size,
        )

        if header_end > max_end:
            return None

        name = str(
            signature.name
        ).strip().upper()

        # ------------------------------------------------------
        # Footer-based formats
        # ------------------------------------------------------

        if signature.footer:

            footer_position = buffer.find(
                signature.footer,
                header_end,
                max_end,
            )

            if footer_position != -1:
                return (
                    footer_position
                    + len(signature.footer)
                )

        # ------------------------------------------------------
        # PNG
        # ------------------------------------------------------

        if name == "PNG":

            position = header_position + 8

            while position + 12 <= max_end:

                length = struct.unpack(
                    ">I",
                    buffer[position:position + 4],
                )[0]

                chunk_end = (
                    position
                    + 8
                    + length
                    + 4
                )

                if chunk_end > max_end:
                    return None

                chunk_type = buffer[
                    position + 4:
                    position + 8
                ]

                if chunk_type == b"IEND":
                    return chunk_end

                position = chunk_end

            return None

        # ------------------------------------------------------
        # SQLite
        # ------------------------------------------------------

        if name in (
            "SQLITE",
            "SQLITE DATABASE",
        ):

            if header_position + 100 > max_end:
                return None

            header = buffer[
                header_position:
                header_position + 100
            ]

            try:
                page_size = struct.unpack(
                    ">H",
                    header[16:18],
                )[0]

                page_count = struct.unpack(
                    ">I",
                    header[28:32],
                )[0]

            except struct.error:
                return None

            if page_size == 1:
                page_size = 65536

            if (
                page_size < 512
                or page_size > 65536
            ):
                return None

            if page_count == 0:
                return None

            database_size = (
                page_size
                * page_count
            )

            end = (
                header_position
                + database_size
            )

            if end <= max_end:
                return end

            return None

        # ------------------------------------------------------
        # BMP
        # ------------------------------------------------------

        if name == "BMP":

            if header_position + 6 > max_end:
                return None

            try:
                declared_size = struct.unpack(
                    "<I",
                    buffer[
                        header_position + 2:
                        header_position + 6
                    ],
                )[0]

            except struct.error:
                return None

            if (
                declared_size >= 54
                and declared_size <= signature.max_size
            ):

                end = (
                    header_position
                    + declared_size
                )

                if end <= max_end:
                    return end

            return None

        # ------------------------------------------------------
        # GIF
        # ------------------------------------------------------

        if name == "GIF":

            position = buffer.find(
                b"\x3B",
                header_end,
                max_end,
            )

            if position != -1:
                return position + 1

            return None

        # ------------------------------------------------------
        # JPEG
        # ------------------------------------------------------

        if name == "JPEG":

            position = buffer.find(
                b"\xFF\xD9",
                header_end,
                max_end,
            )

            if position != -1:
                return position + 2

            return None

        # ------------------------------------------------------
        # PDF
        # ------------------------------------------------------

        if name == "PDF":

            position = buffer.rfind(
                b"%%EOF",
                header_end,
                max_end,
            )

            if position != -1:
                return position + 5

            return None

        # ------------------------------------------------------
        # MP4
        # ------------------------------------------------------

        if name in (
            "MP4",
            "MP4/ISO-BMFF",
            "ISO-BMFF",
        ):

            return self._find_mp4_end(
                buffer,
                header_position,
                max_end,
            )

        # ------------------------------------------------------
        # PE
        # ------------------------------------------------------

        if name in (
            "EXE",
            "WINDOWS PE",
            "PE",
        ):

            return self._find_pe_end(
                buffer,
                header_position,
                max_end,
            )

        # ------------------------------------------------------
        # Unknown no-footer format
        # ------------------------------------------------------

        return None

    # ==========================================================
    # MP4 END
    # ==========================================================

    @staticmethod
    def _find_mp4_end(
        buffer: bytes,
        start: int,
        max_end: int,
    ) -> Optional[int]:

        position = start
        saw_ftyp = False
        saw_moov = False
        box_count = 0

        while position + 8 <= max_end:

            if box_count >= FileCarver.MAX_MP4_BOXES:
                return None

            try:
                size = struct.unpack(
                    ">I",
                    buffer[
                        position:
                        position + 4
                    ],
                )[0]

            except struct.error:
                return None

            box_type = buffer[
                position + 4:
                position + 8
            ]

            header_size = 8

            if size == 1:

                if position + 16 > max_end:
                    return None

                try:
                    size = struct.unpack(
                        ">Q",
                        buffer[
                            position + 8:
                            position + 16
                        ],
                    )[0]

                except struct.error:
                    return None

                header_size = 16

            elif size == 0:

                # Box extends to available boundary.
                return max_end if saw_ftyp else None

            if size < header_size:
                return None

            new_position = position + size

            if new_position > max_end:
                return None

            if box_type == b"ftyp":
                saw_ftyp = True

            if box_type == b"moov":
                saw_moov = True

            position = new_position
            box_count += 1

            # A complete ftyp + moov gives a useful
            # structural boundary.
            if saw_ftyp and saw_moov:
                return position

        return None

    # ==========================================================
    # PE END
    # ==========================================================

    @staticmethod
    def _find_pe_end(
        buffer: bytes,
        start: int,
        max_end: int,
    ) -> Optional[int]:

        if start + 64 > max_end:
            return None

        if buffer[
            start:
            start + 2
        ] != b"MZ":
            return None

        try:
            pe_offset = struct.unpack(
                "<I",
                buffer[
                    start + 60:
                    start + 64
                ],
            )[0]

            pe_start = (
                start
                + pe_offset
            )

            if (
                pe_start + 24
                > max_end
            ):
                return None

            if buffer[
                pe_start:
                pe_start + 4
            ] != b"PE\x00\x00":
                return None

            sections = struct.unpack(
                "<H",
                buffer[
                    pe_start + 6:
                    pe_start + 8
                ],
            )[0]

            optional_size = struct.unpack(
                "<H",
                buffer[
                    pe_start + 20:
                    pe_start + 22
                ],
            )[0]

            if (
                sections == 0
                or sections > FileCarver.MAX_PE_SECTIONS
            ):
                return None

            section_table = (
                pe_start
                + 24
                + optional_size
            )

            section_table_end = (
                section_table
                + sections * 40
            )

            if section_table_end > max_end:
                return None

            artifact_end = section_table_end

            for index in range(sections):

                section = (
                    section_table
                    + index * 40
                )

                raw_size = struct.unpack(
                    "<I",
                    buffer[
                        section + 16:
                        section + 20
                    ],
                )[0]

                raw_pointer = struct.unpack(
                    "<I",
                    buffer[
                        section + 20:
                        section + 24
                    ],
                )[0]

                if raw_size == 0:
                    continue

                section_end = (
                    start
                    + raw_pointer
                    + raw_size
                )

                if section_end > max_end:
                    return None

                artifact_end = max(
                    artifact_end,
                    section_end,
                )

            if artifact_end > max_end:
                return None

            return artifact_end

        except struct.error:
            return None

    # ==========================================================
    # ARTIFACT KEY
    # ==========================================================

    @staticmethod
    def _artifact_key(
        artifact: Dict[str, Any],
    ) -> str:

        return (
            f"{artifact.get('type', '')}:"
            f"{artifact.get('source_offset', -1)}:"
            f"{artifact.get('sha256', '')}"
        )

    # ==========================================================
    # CARVE BUFFER
    # ==========================================================

    def carve_buffer(
        self,
        buffer: bytes,
        start_offset: int = 0,
    ) -> List[Dict[str, Any]]:

        if not buffer:
            return []

        results: List[Dict[str, Any]] = []

        buffer_length = len(buffer)

        for signature in self.signatures:

            header = signature.header

            if not header:
                continue

            header_length = len(header)

            search_position = 0

            while search_position < buffer_length:

                header_position = buffer.find(
                    header,
                    search_position,
                )

                if header_position == -1:
                    break

                absolute_offset = (
                    start_offset
                    + header_position
                )

                carve_end = self._find_carve_end(
                    buffer,
                    header_position,
                    signature,
                )

                if carve_end is None:

                    search_position = (
                        header_position
                        + header_length
                    )

                    continue

                if carve_end <= header_position:

                    search_position = (
                        header_position
                        + header_length
                    )

                    continue

                file_bytes = buffer[
                    header_position:
                    carve_end
                ]

                validation_status, reason = (
                    self._validate_format(
                        file_bytes,
                        signature,
                    )
                )

                # Never register rejected artifacts.
                if validation_status == self.REJECTED:

                    search_position = (
                        header_position
                        + header_length
                    )

                    continue

                hashes = (
                    CryptographicHasher
                    .calculate_bytes_hashes(
                        file_bytes
                    )
                )

                sha256 = str(
                    hashes.get(
                        "sha256",
                        ""
                    )
                )

                md5 = str(
                    hashes.get(
                        "md5",
                        ""
                    )
                )

                artifact_key = (
                    f"{signature.name}:"
                    f"{absolute_offset}:"
                    f"{sha256}"
                )

                # Important:
                # overlapping chunks can rediscover the
                # same artifact. Prevent writing duplicates.
                if artifact_key in self._written_keys:

                    search_position = max(
                        header_position + header_length,
                        carve_end,
                    )

                    continue

                artifact_id = (
                    f"ART-"
                    f"{uuid.uuid4().hex[:12].upper()}"
                )

                extension = (
                    str(
                        signature.extension
                    ).strip(".")
                    or "bin"
                )

                filename = (
                    f"{artifact_id}.{extension}"
                )

                file_path = os.path.join(
                    self.output_dir,
                    filename,
                )

                try:
                    with open(
                        file_path,
                        "xb",
                    ) as recovered_file:

                        recovered_file.write(
                            file_bytes
                        )

                except FileExistsError:

                    # Extremely unlikely because artifact IDs
                    # are UUID-based.
                    search_position = max(
                        header_position + header_length,
                        carve_end,
                    )
                    continue

                except OSError:

                    search_position = (
                        header_position
                        + header_length
                    )

                    continue

                entropy = (
                    self.calculate_entropy(
                        file_bytes
                    )
                )

                entropy_class = (
                    self._classify_entropy(
                        entropy
                    )
                )

                artifact = {
                    "artifact_id": artifact_id,

                    "name": filename,

                    "type": signature.name,

                    "category": signature.category,

                    "extension": extension,

                    "mime_type": signature.mime_type,

                    "offset": absolute_offset,

                    "source_offset": absolute_offset,

                    "size": len(file_bytes),

                    "sha256": sha256,

                    "md5": md5,

                    "entropy": entropy,

                    "entropy_class": entropy_class,

                    "recovery_method":
                        "SIGNATURE_CARVING",

                    "validation_status":
                        validation_status,

                    # Compatibility with your Node/frontend.
                    "validationStatus":
                        validation_status,

                    "validation_reason":
                        reason,

                    "status":
                        (
                            "VALIDATED"
                            if validation_status
                            == self.VALIDATED
                            else "RECOVERED"
                        ),

                    "file_path":
                        os.path.abspath(
                            file_path
                        ),

                    "source_range": {
                        "start":
                            absolute_offset,
                        "end":
                            absolute_offset
                            + len(file_bytes),
                        "length":
                            len(file_bytes),
                    },
                }

                results.append(
                    artifact
                )

                self._written_keys.add(
                    artifact_key
                )

                search_position = max(
                    header_position
                    + header_length,
                    carve_end,
                )

        return results

    # ==========================================================
    # CARVE FILE
    # ==========================================================

    def carve_file(
        self,
        target_path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> List[Dict[str, Any]]:

        target_path = os.path.abspath(
            target_path
        )

        if not os.path.isfile(
            target_path
        ):
            raise FileNotFoundError(
                "Target file for carving not found: "
                f"{target_path}"
            )

        if chunk_size <= 0:
            raise ValueError(
                "chunk_size must be greater than zero"
            )

        file_size = os.path.getsize(
            target_path
        )

        if file_size == 0:
            return []

        results: List[
            Dict[str, Any]
        ] = []

        overlap = min(
            self.DEFAULT_OVERLAP,
            max(0, chunk_size // 2),
        )

        previous_tail = b""

        current_offset = 0

        with open(
            target_path,
            "rb",
        ) as evidence_file:

            while current_offset < file_size:

                chunk = evidence_file.read(
                    chunk_size
                )

                if not chunk:
                    break

                full_buffer = (
                    previous_tail
                    + chunk
                )

                buffer_start_offset = (
                    current_offset
                    - len(previous_tail)
                )

                carved = self.carve_buffer(
                    full_buffer,
                    start_offset=buffer_start_offset,
                )

                results.extend(
                    carved
                )

                if len(chunk) >= overlap:
                    previous_tail = (
                        chunk[-overlap:]
                    )
                else:
                    previous_tail = chunk

                current_offset += len(chunk)

        # Final safety deduplication.
        unique_results: Dict[
            str,
            Dict[str, Any]
        ] = {}

        for artifact in results:

            key = self._artifact_key(
                artifact
            )

            if key not in unique_results:
                unique_results[key] = artifact

        return list(
            unique_results.values()
        )