import hashlib
import os
from typing import Dict, Union, BinaryIO

class CryptographicHasher:
    """
    Computes cryptographic hashes for files and byte streams 
    for evidence verification and chain-of-custody tracking.
    """
    @staticmethod
    def calculate_file_hashes(file_path: str, chunk_size: int = 65536) -> Dict[str, str]:
        """
        Calculates SHA256, MD5, and SHA1 hashes for a target file on disk.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target evidence file not found: {file_path}")

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)

        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "file_size": os.path.getsize(file_path)
        }

    @staticmethod
    def calculate_bytes_hashes(data: bytes) -> Dict[str, str]:
        """
        Calculates hashes for in-memory byte buffer.
        """
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "size_bytes": len(data)
        }
