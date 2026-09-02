import os
import re
import struct
import time
from typing import Dict, Any

class MetadataExtractor:
    """
    Parses structural metadata, EXIF tags, header properties,
    and filesystem metrics from evidence items and carved artifacts.
    """
    @staticmethod
    def extract_file_metadata(file_path: str) -> Dict[str, Any]:
        """
        Extracts comprehensive metadata for a given file.
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        stat = os.stat(file_path)
        ext = os.path.splitext(file_path)[1].lower().strip('.')

        meta = {
            "filename": os.path.basename(file_path),
            "extension": ext,
            "size_bytes": stat.st_size,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_ctime)),
            "modified_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
            "accessed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_atime)),
            "attributes": {
                "readonly": not os.access(file_path, os.W_OK),
                "executable": os.access(file_path, os.X_OK)
            },
            "format_details": {}
        }

        # Format-specific header parsing
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)
                
                if ext in ['jpg', 'jpeg'] and header.startswith(b'\xFF\xD8'):
                    meta["format_details"] = MetadataExtractor._parse_jpeg_header(header)
                elif ext == 'pdf' and b'%PDF-' in header:
                    meta["format_details"] = MetadataExtractor._parse_pdf_header(f, stat.st_size)
                elif ext == 'zip' or header.startswith(b'PK\x03\x04'):
                    meta["format_details"] = {"compression": "Zip Archive", "signature": "PKZip"}
                elif ext == 'png' and header.startswith(b'\x89PNG'):
                    if len(header) >= 24:
                        width, height = struct.unpack('>II', header[16:24])
                        meta["format_details"] = {"dimensions": f"{width}x{height}", "color_depth": "8/16-bit PNG"}
        except Exception as e:
            meta["format_details"]["parse_error"] = str(e)

        return meta

    @staticmethod
    def _parse_jpeg_header(header: bytes) -> Dict[str, Any]:
        info = {"type": "JPEG Image"}
        if b'JFIF' in header:
            info["format"] = "JFIF"
        elif b'Exif' in header:
            info["format"] = "EXIF Metadata Present"
        return info

    @staticmethod
    def _parse_pdf_header(file_obj, file_size: int) -> Dict[str, Any]:
        info = {"type": "PDF Document"}
        file_obj.seek(0)
        content = file_obj.read(min(file_size, 4096)).decode('latin1', errors='ignore')
        version_match = re.search(r'%PDF-(\d\.\d)', content)
        if version_match:
            info["pdf_version"] = version_match.group(1)
        if '/Title' in content:
            info["has_title"] = True
        if '/Producer' in content:
            info["has_producer"] = True
        return info
