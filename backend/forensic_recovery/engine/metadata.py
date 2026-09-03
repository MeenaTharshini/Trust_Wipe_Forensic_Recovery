import mimetypes
import os
import re
import struct
import time
import zipfile

from typing import Any, Dict, List, Optional


class MetadataExtractor:
    """
    Production-oriented forensic metadata extractor.

    Extracts:

        - file identity
        - filesystem timestamps
        - filesystem attributes
        - MIME information
        - magic/signature-based format
        - format-specific structural metadata
        - basic integrity indicators

    Important:

        This module performs read-only analysis.

        Metadata extraction does NOT prove:
            - authenticity
            - ownership
            - legal admissibility
            - physical-media sanitization
            - regulatory compliance
    """

    MAX_HEADER_READ = 4096
    MAX_TEXT_SCAN = 1024 * 1024
    MAX_JPEG_SCAN = 4 * 1024 * 1024
    MAX_MP3_SCAN = 1024 * 1024
    MAX_MP4_BOX_SCAN = 16 * 1024 * 1024
    MAX_ZIP_MEMBERS = 100_000

    # ==========================================================
    # MAIN ENTRY POINT
    # ==========================================================

    @staticmethod
    def extract_file_metadata(
        file_path: str,
    ) -> Dict[str, Any]:

        if not os.path.isfile(file_path):

            return {
                "error":
                    f"File not found: {file_path}"
            }

        file_path = os.path.abspath(
            file_path
        )

        try:
            stat = os.stat(
                file_path
            )

        except OSError as exc:

            return {
                "error":
                    f"Unable to stat file: {exc}"
            }

        filename = os.path.basename(
            file_path
        )

        extension = (
            os.path.splitext(
                filename
            )[1]
            .lower()
            .lstrip(".")
        )

        mime_type, _ = (
            mimetypes.guess_type(
                file_path
            )
        )

        metadata: Dict[str, Any] = {

            "filename":
                filename,

            "absolute_path":
                file_path,

            "extension":
                extension,

            "mime_type":
                mime_type,

            "size_bytes":
                stat.st_size,

            "created_utc":
                MetadataExtractor._utc_timestamp(
                    stat.st_ctime
                ),

            "modified_utc":
                MetadataExtractor._utc_timestamp(
                    stat.st_mtime
                ),

            "accessed_utc":
                MetadataExtractor._utc_timestamp(
                    stat.st_atime
                ),

            "timestamp_sources": {
                "created":
                    MetadataExtractor._ctime_description(),
                "modified":
                    "filesystem modification timestamp",
                "accessed":
                    "filesystem access timestamp",
            },

            "attributes": {
                "readonly":
                    not os.access(
                        file_path,
                        os.W_OK,
                    ),

                "executable":
                    os.access(
                        file_path,
                        os.X_OK,
                    ),

                "regular_file":
                    os.path.isfile(
                        file_path
                    ),
            },

            "format_details": {},
        }

        try:

            with open(
                file_path,
                "rb",
            ) as file_obj:

                header = file_obj.read(
                    MetadataExtractor.MAX_HEADER_READ
                )

                detected_format = (
                    MetadataExtractor.detect_format(
                        header
                    )
                )

                metadata[
                    "detected_format"
                ] = detected_format

                metadata[
                    "format_details"
                ] = (
                    MetadataExtractor
                    ._extract_format_metadata(
                        file_obj=file_obj,
                        header=header,
                        file_size=stat.st_size,
                        extension=extension,
                    )
                )

        except (
            OSError,
            ValueError,
            struct.error,
        ) as exc:

            metadata[
                "format_details"
            ] = {
                "parse_error":
                    str(exc)
            }

        return metadata

    # ==========================================================
    # TIME
    # ==========================================================

    @staticmethod
    def _utc_timestamp(
        timestamp: float,
    ) -> str:

        return time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(timestamp),
        )

    @staticmethod
    def _ctime_description() -> str:

        if os.name == "nt":
            return (
                "Windows filesystem creation/change timestamp"
            )

        return (
            "Unix filesystem metadata-change timestamp; "
            "not necessarily file creation time"
        )

    # ==========================================================
    # FORMAT DETECTION
    # ==========================================================

    @staticmethod
    def detect_format(
        data: bytes,
    ) -> str:

        if data.startswith(
            b"\xFF\xD8\xFF"
        ):
            return "JPEG"

        if data.startswith(
            b"\x89PNG\r\n\x1a\n"
        ):
            return "PNG"

        if data.startswith(
            b"%PDF-"
        ):
            return "PDF"

        if (
            data.startswith(
                b"PK\x03\x04"
            )
            or data.startswith(
                b"PK\x05\x06"
            )
            or data.startswith(
                b"PK\x07\x08"
            )
        ):
            return "ZIP"

        if data.startswith(
            b"GIF87a"
        ) or data.startswith(
            b"GIF89a"
        ):
            return "GIF"

        if data.startswith(
            b"BM"
        ):
            return "BMP"

        if data.startswith(
            b"SQLite format 3\x00"
        ):
            return "SQLite"

        if len(data) >= 12:

            if data[4:8] == b"ftyp":
                return "MP4/ISO-BMFF"

        if data.startswith(
            b"MZ"
        ):

            if len(data) >= 64:

                try:

                    pe_offset = struct.unpack(
                        "<I",
                        data[60:64],
                    )[0]

                    if (
                        pe_offset >= 64
                        and pe_offset + 4 <= len(data)
                        and data[
                            pe_offset:
                            pe_offset + 4
                        ] == b"PE\x00\x00"
                    ):
                        return "Windows PE"

                except struct.error:
                    pass

            return "DOS/PE Candidate"

        if data.startswith(
            b"ID3"
        ):
            return "MP3"

        if MetadataExtractor._has_mp3_frame(
            data
        ):
            return "MP3"

        if data.startswith(
            b"{\\rtf"
        ):
            return "RTF"

        return "UNKNOWN"

    # ==========================================================
    # FORMAT DISPATCH
    # ==========================================================

    @staticmethod
    def _extract_format_metadata(
        file_obj,
        header: bytes,
        file_size: int,
        extension: str,
    ) -> Dict[str, Any]:

        detected = (
            MetadataExtractor.detect_format(
                header
            )
        )

        if detected == "JPEG":
            return MetadataExtractor._parse_jpeg(
                file_obj
            )

        if detected == "PNG":
            return MetadataExtractor._parse_png(
                file_obj
            )

        if detected == "PDF":
            return MetadataExtractor._parse_pdf(
                file_obj,
                file_size,
            )

        if detected == "ZIP":
            return MetadataExtractor._parse_zip(
                file_obj
            )

        if detected == "SQLite":
            return MetadataExtractor._parse_sqlite(
                file_obj,
                file_size,
            )

        if detected == "MP4/ISO-BMFF":
            return MetadataExtractor._parse_mp4(
                file_obj,
                file_size,
            )

        if detected == "Windows PE":
            return MetadataExtractor._parse_pe(
                file_obj,
                file_size,
            )

        if detected == "GIF":
            return MetadataExtractor._parse_gif(
                file_obj
            )

        if detected == "BMP":
            return MetadataExtractor._parse_bmp(
                file_obj
            )

        if detected == "MP3":
            return MetadataExtractor._parse_mp3(
                file_obj,
                file_size,
            )

        if detected == "RTF":
            return MetadataExtractor._parse_rtf(
                file_obj
            )

        return {
            "type": detected,
            "extension": extension,
        }

    # ==========================================================
    # JPEG
    # ==========================================================

    @staticmethod
    def _parse_jpeg(
        file_obj,
    ) -> Dict[str, Any]:

        file_obj.seek(0)

        data = file_obj.read(
            MetadataExtractor.MAX_JPEG_SCAN
        )

        info: Dict[str, Any] = {

            "type":
                "JPEG Image",

            "format":
                "JPEG",

            "has_exif":
                b"Exif\x00\x00" in data,

            "has_jfif":
                b"JFIF" in data,

            "dimensions":
                None,

            "width":
                None,

            "height":
                None,

            "end_marker_present":
                data.endswith(
                    b"\xFF\xD9"
                ),

            "sof_marker":
                None,
        }

        dimensions = (
            MetadataExtractor
            ._find_jpeg_dimensions(
                data
            )
        )

        if dimensions:

            width, height, marker = (
                dimensions
            )

            info["width"] = width
            info["height"] = height

            info["dimensions"] = (
                f"{width}x{height}"
            )

            info["sof_marker"] = (
                f"0x{marker:02X}"
            )

        if info["has_jfif"]:
            info["format"] = "JFIF"

        elif info["has_exif"]:
            info["format"] = "EXIF JPEG"

        return info

    @staticmethod
    def _find_jpeg_dimensions(
        data: bytes,
    ) -> Optional[
        tuple
    ]:

        if not data.startswith(
            b"\xFF\xD8"
        ):
            return None

        pos = 2

        while pos + 4 <= len(data):

            if data[pos] != 0xFF:

                pos += 1
                continue

            while (
                pos < len(data)
                and data[pos] == 0xFF
            ):
                pos += 1

            if pos >= len(data):
                break

            marker = data[pos]

            if marker == 0xD9:
                break

            if marker in (
                0x01,
                *range(0xD0, 0xD8),
            ):

                pos += 1
                continue

            if pos + 3 > len(data):
                break

            segment_length = struct.unpack(
                ">H",
                data[
                    pos + 1:
                    pos + 3
                ],
            )[0]

            if segment_length < 2:
                break

            segment_end = (
                pos
                + 1
                + segment_length
            )

            if segment_end > len(data):
                break

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

                if segment_length < 7:
                    return None

                height = struct.unpack(
                    ">H",
                    data[
                        pos + 4:
                        pos + 6
                    ],
                )[0]

                width = struct.unpack(
                    ">H",
                    data[
                        pos + 6:
                        pos + 8
                    ],
                )[0]

                if width == 0 or height == 0:
                    return None

                return (
                    width,
                    height,
                    marker,
                )

            pos = segment_end

        return None

    # ==========================================================
    # PNG
    # ==========================================================

    @staticmethod
    def _parse_png(
        file_obj,
    ) -> Dict[str, Any]:

        file_obj.seek(0)

        header = file_obj.read(33)

        info: Dict[str, Any] = {

            "type":
                "PNG Image",

            "dimensions":
                None,

            "width":
                None,

            "height":
                None,

            "bit_depth":
                None,

            "color_type":
                None,

            "interlace_method":
                None,

            "has_iend":
                False,

            "chunk_count":
                0,

            "crc_errors":
                0,
        }

        if (
            len(header) >= 33
            and header.startswith(
                b"\x89PNG\r\n\x1a\n"
            )
        ):

            width, height = struct.unpack(
                ">II",
                header[16:24],
            )

            bit_depth = header[24]
            color_type = header[25]
            interlace = header[28]

            info["width"] = width
            info["height"] = height

            info["dimensions"] = (
                f"{width}x{height}"
            )

            info["bit_depth"] = (
                bit_depth
            )

            info["color_type"] = (
                MetadataExtractor
                ._png_color_type_name(
                    color_type
                )
            )

            info["interlace_method"] = (
                "Adam7"
                if interlace == 1
                else "None"
            )

        file_obj.seek(0)

        position = 8

        while True:

            raw = file_obj.read(8)

            if len(raw) < 8:
                break

            length = struct.unpack(
                ">I",
                raw[:4],
            )[0]

            chunk_type = raw[4:8]

            # Avoid pathological allocations.
            if length > 256 * 1024 * 1024:
                break

            chunk_data = file_obj.read(
                length
            )

            crc = file_obj.read(4)

            if len(chunk_data) != length:
                break

            if len(crc) != 4:
                break

            info["chunk_count"] += 1

            stored_crc = struct.unpack(
                ">I",
                crc,
            )[0]

            calculated_crc = (
                zlib_crc32(
                    chunk_type
                    + chunk_data
                )
            )

            if stored_crc != calculated_crc:
                info["crc_errors"] += 1

            if chunk_type == b"IEND":
                info["has_iend"] = True
                break

        return info

    @staticmethod
    def _png_color_type_name(
        color_type: int,
    ) -> str:

        names = {
            0: "Grayscale",
            2: "Truecolor",
            3: "Indexed-color",
            4: "Grayscale + Alpha",
            6: "Truecolor + Alpha",
        }

        return names.get(
            color_type,
            f"Unknown ({color_type})",
        )

    # ==========================================================
    # PDF
    # ==========================================================

    @staticmethod
    def _parse_pdf(
        file_obj,
        file_size: int,
    ) -> Dict[str, Any]:

        file_obj.seek(0)

        content = file_obj.read(
            min(
                file_size,
                MetadataExtractor.MAX_TEXT_SCAN,
            )
        )

        text = content.decode(
            "latin1",
            errors="ignore",
        )

        version_match = re.search(
            rb"%PDF-(\d+\.\d+)",
            content,
        )

        return {
            "type":
                "PDF Document",

            "pdf_version":
                (
                    version_match.group(1)
                    .decode(
                        "ascii",
                        errors="ignore",
                    )
                    if version_match
                    else None
                ),

            "has_eof_marker":
                b"%%EOF" in content,

            "has_xref":
                b"xref" in content,

            "has_xref_stream":
                b"/Type/XRef" in content
                or b"/Type /XRef" in content,

            "has_title":
                b"/Title" in content,

            "has_producer":
                b"/Producer" in content,

            "has_creator":
                b"/Creator" in content,

            "has_metadata_object":
                b"/Metadata" in content,
        }

    # ==========================================================
    # ZIP
    # ==========================================================

    @staticmethod
    def _parse_zip(
        file_obj,
    ) -> Dict[str, Any]:

        info: Dict[str, Any] = {

            "type":
                "ZIP Archive",

            "valid_zip_structure":
                False,

            "member_count":
                0,

            "compressed_size":
                0,

            "uncompressed_size":
                0,

            "members":
                [],

            "crc_validation":
                "NOT_CHECKED",
        }

        file_obj.seek(0)

        try:

            with zipfile.ZipFile(
                file_obj,
                "r",
            ) as archive:

                members = archive.infolist()

                if len(members) > MetadataExtractor.MAX_ZIP_MEMBERS:

                    info[
                        "parse_error"
                    ] = (
                        "ZIP contains an excessive number of members"
                    )

                    return info

                bad_file = archive.testzip()

                info[
                    "valid_zip_structure"
                ] = (
                    bad_file is None
                )

                info[
                    "crc_validation"
                ] = (
                    "PASSED"
                    if bad_file is None
                    else f"FAILED: {bad_file}"
                )

                info[
                    "member_count"
                ] = len(members)

                for item in members:

                    info[
                        "compressed_size"
                    ] += item.compress_size

                    info[
                        "uncompressed_size"
                    ] += item.file_size

                    if len(
                        info["members"]
                    ) < 100:

                        info[
                            "members"
                        ].append(
                            {
                                "filename":
                                    item.filename,

                                "compressed_size":
                                    item.compress_size,

                                "uncompressed_size":
                                    item.file_size,

                                "compression":
                                    item.compress_type,

                                "is_directory":
                                    item.is_dir(),
                            }
                        )

        except (
            zipfile.BadZipFile,
            OSError,
            RuntimeError,
        ) as exc:

            info[
                "parse_error"
            ] = str(exc)

        return info

    # ==========================================================
    # SQLITE
    # ==========================================================

    @staticmethod
    def _parse_sqlite(
        file_obj,
        file_size: int,
    ) -> Dict[str, Any]:

        file_obj.seek(0)

        header = file_obj.read(100)

        info: Dict[str, Any] = {

            "type":
                "SQLite Database",

            "header_valid":
                False,

            "page_size":
                None,

            "page_count":
                None,

            "calculated_database_size":
                None,

            "database_size_matches":
                False,

            "write_version":
                None,

            "read_version":
                None,

            "schema_format":
                None,

            "text_encoding":
                None,
        }

        if len(header) < 100:
            return info

        if not header.startswith(
            b"SQLite format 3\x00"
        ):
            return info

        info["header_valid"] = True

        page_size = struct.unpack(
            ">H",
            header[16:18],
        )[0]

        if page_size == 1:
            page_size = 65536

        page_count = struct.unpack(
            ">I",
            header[28:32],
        )[0]

        write_version = header[18]
        read_version = header[19]

        schema_format = struct.unpack(
            ">I",
            header[44:48],
        )[0]

        text_encoding = struct.unpack(
            ">I",
            header[56:60],
        )[0]

        info["page_size"] = page_size
        info["page_count"] = page_count
        info["write_version"] = write_version
        info["read_version"] = read_version
        info["schema_format"] = schema_format

        text_encodings = {
            1: "UTF-8",
            2: "UTF-16LE",
            3: "UTF-16BE",
        }

        info["text_encoding"] = (
            text_encodings.get(
                text_encoding,
                f"Unknown ({text_encoding})",
            )
        )

        if page_count > 0:

            calculated_size = (
                page_size
                * page_count
            )

            info[
                "calculated_database_size"
            ] = calculated_size

            info[
                "database_size_matches"
            ] = (
                calculated_size
                <= file_size
            )

        return info

    # ==========================================================
    # MP4 / ISO-BMFF
    # ==========================================================

    @staticmethod
    def _parse_mp4(
        file_obj,
        file_size: int,
    ) -> Dict[str, Any]:

        info: Dict[str, Any] = {

            "type":
                "MP4 / ISO-BMFF",

            "major_brand":
                None,

            "minor_version":
                None,

            "compatible_brands":
                [],

            "box_count":
                0,

            "top_level_boxes":
                [],

            "parse_complete":
                False,
        }

        file_obj.seek(0)

        header = file_obj.read(32)

        if len(header) < 16:
            return info

        if header[4:8] != b"ftyp":
            return info

        try:

            ftyp_size = struct.unpack(
                ">I",
                header[:4],
            )[0]

            info[
                "major_brand"
            ] = header[
                8:12
            ].decode(
                "latin1",
                errors="ignore",
            )

            info[
                "minor_version"
            ] = struct.unpack(
                ">I",
                header[12:16],
            )[0]

            brand_end = min(
                ftyp_size,
                len(header),
            )

            for pos in range(
                16,
                brand_end,
                4,
            ):

                if pos + 4 <= brand_end:

                    brand = header[
                        pos:
                        pos + 4
                    ]

                    info[
                        "compatible_brands"
                    ].append(
                        brand.decode(
                            "latin1",
                            errors="ignore",
                        )
                    )

        except struct.error:
            return info

        file_obj.seek(0)

        scanned = 0

        while (
            scanned + 8 <= file_size
            and scanned
            < MetadataExtractor.MAX_MP4_BOX_SCAN
        ):

            box_header = file_obj.read(8)

            if len(box_header) < 8:
                break

            box_size = struct.unpack(
                ">I",
                box_header[:4],
            )[0]

            box_type = box_header[
                4:8
            ].decode(
                "latin1",
                errors="ignore",
            )

            header_size = 8

            if box_size == 1:

                extended = file_obj.read(8)

                if len(extended) < 8:
                    break

                box_size = struct.unpack(
                    ">Q",
                    extended,
                )[0]

                header_size = 16

            elif box_size == 0:

                # Extends to EOF.
                box_size = (
                    file_size
                    - scanned
                )

            if box_size < header_size:
                break

            if (
                scanned
                + box_size
                > file_size
            ):
                break

            info["box_count"] += 1

            if len(
                info["top_level_boxes"]
            ) < 50:

                info[
                    "top_level_boxes"
                ].append(
                    {
                        "type":
                            box_type,

                        "size":
                            box_size,

                        "offset":
                            scanned,
                    }
                )

            skip = (
                box_size
                - header_size
            )

            file_obj.seek(
                skip,
                os.SEEK_CUR,
            )

            scanned += box_size

            if box_size == 0:
                break

        info[
            "parse_complete"
        ] = (
            scanned == file_size
        )

        return info

    # ==========================================================
    # PE / EXE
    # ==========================================================

    @staticmethod
    def _parse_pe(
        file_obj,
        file_size: int,
    ) -> Dict[str, Any]:

        info: Dict[str, Any] = {

            "type":
                "Windows PE",

            "mz_header":
                False,

            "pe_signature":
                False,

            "machine":
                None,

            "machine_code":
                None,

            "number_of_sections":
                None,

            "pe_offset":
                None,

            "optional_header_magic":
                None,

            "sections":
                [],
        }

        file_obj.seek(0)

        dos_header = file_obj.read(64)

        if len(dos_header) < 64:
            return info

        if dos_header[:2] != b"MZ":
            return info

        info["mz_header"] = True

        pe_offset = struct.unpack(
            "<I",
            dos_header[60:64],
        )[0]

        info["pe_offset"] = pe_offset

        if (
            pe_offset < 64
            or pe_offset + 24 > file_size
        ):
            return info

        file_obj.seek(
            pe_offset
        )

        pe_header = file_obj.read(
            24
        )

        if len(pe_header) < 24:
            return info

        if pe_header[:4] != b"PE\x00\x00":
            return info

        info[
            "pe_signature"
        ] = True

        machine = struct.unpack(
            "<H",
            pe_header[4:6],
        )[0]

        section_count = struct.unpack(
            "<H",
            pe_header[6:8],
        )[0]

        optional_size = struct.unpack(
            "<H",
            pe_header[20:22],
        )[0]

        info[
            "machine_code"
        ] = (
            f"0x{machine:04X}"
        )

        info[
            "machine"
        ] = (
            MetadataExtractor
            ._machine_name(
                machine
            )
        )

        info[
            "number_of_sections"
        ] = section_count

        optional_header = file_obj.read(
            optional_size
        )

        if len(optional_header) >= 2:

            magic = struct.unpack(
                "<H",
                optional_header[:2],
            )[0]

            info[
                "optional_header_magic"
            ] = (
                f"0x{magic:04X}"
            )

        section_table = (
            pe_offset
            + 24
            + optional_size
        )

        file_obj.seek(
            section_table
        )

        for _ in range(
            min(
                section_count,
                96,
            )
        ):

            section = file_obj.read(
                40
            )

            if len(section) < 40:
                break

            name = (
                section[:8]
                .rstrip(b"\x00")
                .decode(
                    "latin1",
                    errors="ignore",
                )
            )

            virtual_size = struct.unpack(
                "<I",
                section[8:12],
            )[0]

            virtual_address = struct.unpack(
                "<I",
                section[12:16],
            )[0]

            raw_size = struct.unpack(
                "<I",
                section[16:20],
            )[0]

            raw_pointer = struct.unpack(
                "<I",
                section[20:24],
            )[0]

            info[
                "sections"
            ].append(
                {
                    "name":
                        name,

                    "virtual_size":
                        virtual_size,

                    "virtual_address":
                        virtual_address,

                    "raw_size":
                        raw_size,

                    "raw_pointer":
                        raw_pointer,
                }
            )

        return info

    @staticmethod
    def _machine_name(
        machine: int,
    ) -> str:

        machines = {
            0x014C: "x86",
            0x8664: "x64",
            0x01C0: "ARM",
            0xAA64: "ARM64",
        }

        return machines.get(
            machine,
            f"UNKNOWN(0x{machine:04X})",
        )

    # ==========================================================
    # GIF
    # ==========================================================

    @staticmethod
    def _parse_gif(
        file_obj,
    ) -> Dict[str, Any]:

        file_obj.seek(0)

        header = file_obj.read(
            13
        )

        info = {

            "type":
                "GIF Image",

            "version":
                None,

            "dimensions":
                None,

            "width":
                None,

            "height":
                None,

            "color_resolution":
                None,

            "global_color_table":
                False,

            "trailer_present":
                False,
        }

        if len(header) < 13:
            return info

        info[
            "version"
        ] = header[
            3:6
        ].decode(
            "ascii",
            errors="ignore",
        )

        width = struct.unpack(
            "<H",
            header[6:8],
        )[0]

        height = struct.unpack(
            "<H",
            header[8:10],
        )[0]

        packed = header[10]

        info[
            "width"
        ] = width

        info[
            "height"
        ] = height

        info[
            "dimensions"
        ] = (
            f"{width}x{height}"
        )

        info[
            "global_color_table"
        ] = bool(
            packed & 0x80
        )

        info[
            "color_resolution"
        ] = (
            ((packed >> 4) & 0x07)
            + 1
        )

        file_obj.seek(
            max(
                0,
                os.fstat(
                    file_obj.fileno()
                ).st_size - 32,
            )
        )

        tail = file_obj.read(
            32
        )

        info[
            "trailer_present"
        ] = (
            b"\x3B" in tail
        )

        return info

    # ==========================================================
    # BMP
    # ==========================================================

    @staticmethod
    def _parse_bmp(
        file_obj,
    ) -> Dict[str, Any]:

        file_obj.seek(0)

        header = file_obj.read(
            54
        )

        info = {

            "type":
                "BMP Image",

            "dimensions":
                None,

            "width":
                None,

            "height":
                None,

            "bits_per_pixel":
                None,

            "pixel_data_offset":
                None,
        }

        if len(header) < 54:
            return info

        try:

            width = struct.unpack(
                "<i",
                header[18:22],
            )[0]

            height = struct.unpack(
                "<i",
                header[22:26],
            )[0]

            bpp = struct.unpack(
                "<H",
                header[28:30],
            )[0]

            pixel_offset = struct.unpack(
                "<I",
                header[10:14],
            )[0]

            info[
                "width"
            ] = width

            info[
                "height"
            ] = height

            info[
                "dimensions"
            ] = (
                f"{abs(width)}x{abs(height)}"
            )

            info[
                "bits_per_pixel"
            ] = bpp

            info[
                "pixel_data_offset"
            ] = pixel_offset

        except struct.error:
            pass

        return info

    # ==========================================================
    # MP3
    # ==========================================================

    @staticmethod
    def _parse_mp3(
        file_obj,
        file_size: int,
    ) -> Dict[str, Any]:

        file_obj.seek(0)

        scan_size = min(
            file_size,
            MetadataExtractor.MAX_MP3_SCAN,
        )

        data = file_obj.read(
            scan_size
        )

        info = {

            "type":
                "MP3 Audio",

            "id3v2_present":
                False,

            "id3v1_present":
                False,

            "mpeg_frame_present":
                False,

            "mpeg_version":
                None,

            "layer":
                None,

            "bitrate_index":
                None,

            "sample_rate_index":
                None,

            "first_frame_offset":
                None,
        }

        if data.startswith(
            b"ID3"
        ):

            info[
                "id3v2_present"
            ] = True

        frame = (
            MetadataExtractor
            ._find_mp3_frame(
                data
            )
        )

        if frame:

            offset, details = frame

            info[
                "mpeg_frame_present"
            ] = True

            info[
                "first_frame_offset"
            ] = offset

            info[
                "mpeg_version"
            ] = details[
                "version"
            ]

            info[
                "layer"
            ] = details[
                "layer"
            ]

            info[
                "bitrate_index"
            ] = details[
                "bitrate_index"
            ]

            info[
                "sample_rate_index"
            ] = details[
                "sample_rate_index"
            ]

        if file_size >= 128:

            file_obj.seek(
                file_size - 128
            )

            tail = file_obj.read(
                128
            )

            if tail.startswith(
                b"TAG"
            ):
                info[
                    "id3v1_present"
                ] = True

        return info

    @staticmethod
    def _has_mp3_frame(
        data: bytes,
    ) -> bool:

        return (
            MetadataExtractor
            ._find_mp3_frame(
                data
            )
            is not None
        )

    @staticmethod
    def _find_mp3_frame(
        data: bytes,
    ) -> Optional[
        tuple
    ]:

        limit = min(
            len(data) - 4,
            MetadataExtractor.MAX_MP3_SCAN,
        )

        if limit <= 0:
            return None

        for index in range(
            0,
            limit,
        ):

            first = data[index]
            second = data[index + 1]

            if first != 0xFF:
                continue

            if (
                second & 0xE0
            ) != 0xE0:
                continue

            version_bits = (
                second >> 3
            ) & 0x03

            layer_bits = (
                second >> 1
            ) & 0x03

            if version_bits == 1:
                continue

            if layer_bits == 0:
                continue

            third = data[
                index + 2
            ]

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

            versions = {
                0: "MPEG-2.5",
                2: "MPEG-2",
                3: "MPEG-1",
            }

            layers = {
                1: "Layer III",
                2: "Layer II",
                3: "Layer I",
            }

            return (
                index,
                {
                    "version":
                        versions.get(
                            version_bits,
                            "Unknown",
                        ),

                    "layer":
                        layers.get(
                            layer_bits,
                            "Unknown",
                        ),

                    "bitrate_index":
                        bitrate_index,

                    "sample_rate_index":
                        sample_rate_index,
                },
            )

        return None

    # ==========================================================
    # RTF
    # ==========================================================

    @staticmethod
    def _parse_rtf(
        file_obj,
    ) -> Dict[str, Any]:

        file_obj.seek(0)

        data = file_obj.read(
            MetadataExtractor.MAX_TEXT_SCAN
        )

        text = data.decode(
            "latin1",
            errors="ignore",
        )

        return {

            "type":
                "Rich Text Format",

            "rtf_header":
                text.startswith(
                    r"{\rtf"
                ),

            "has_unicode_escape":
                "\\u" in text,

            "has_font_table":
                "\\fonttbl" in text,

            "has_color_table":
                "\\colortbl" in text,

            "has_stylesheet":
                "\\stylesheet" in text,
        }


# ==============================================================
# STANDALONE CRC HELPER
# ==============================================================

def zlib_crc32(
    data: bytes,
) -> int:

    import zlib

    return (
        zlib.crc32(data)
        & 0xFFFFFFFF
    )