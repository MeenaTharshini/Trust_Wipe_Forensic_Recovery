import os
import sys
import time
from typing import Generator, Dict, Any
from .hashing import CryptographicHasher

class EvidenceAcquisition:
    """
    Manages raw block and stream reading from disk images, raw block devices,
    or target directories for forensic evidence processing.
    """
    def __init__(self, target_path: str, block_size: int = 512):
        self.target_path = target_path
        self.block_size = block_size
        self.total_bytes = 0
        if os.path.exists(target_path):
            if os.path.isfile(target_path):
                self.total_bytes = os.path.getsize(target_path)
            elif os.path.isdir(target_path):
                self.total_bytes = sum(
                    os.path.getsize(os.path.join(r, f))
                    for r, _, files in os.walk(target_path)
                    for f in files
                )

    def read_blocks(self, chunk_size: int = 1048576) -> Generator[Dict[str, Any], None, None]:
        """
        Yields chunked byte blocks along with sector offsets and hashes.
        """
        if not os.path.exists(self.target_path):
            raise FileNotFoundError(f"Evidence target does not exist: {self.target_path}")

        if os.path.isfile(self.target_path):
            offset = 0
            with open(self.target_path, 'rb') as f:
                while True:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    chunk_len = len(data)
                    chunk_hash = CryptographicHasher.calculate_bytes_hashes(data)
                    yield {
                        "offset": offset,
                        "size": chunk_len,
                        "data": data,
                        "sha256": chunk_hash["sha256"],
                        "sector_start": offset // self.block_size,
                        "sector_end": (offset + chunk_len) // self.block_size
                    }
                    offset += chunk_len
        elif os.path.isdir(self.target_path):
            offset = 0
            for root, _, files in os.walk(self.target_path):
                for file_name in files:
                    full_p = os.path.join(root, file_name)
                    try:
                        with open(full_p, 'rb') as f:
                            while True:
                                data = f.read(chunk_size)
                                if not data:
                                    break
                                chunk_len = len(data)
                                yield {
                                    "offset": offset,
                                    "source_file": full_p,
                                    "size": chunk_len,
                                    "data": data,
                                    "sha256": CryptographicHasher.calculate_bytes_hashes(data)["sha256"],
                                    "sector_start": offset // self.block_size,
                                    "sector_end": (offset + chunk_len) // self.block_size
                                }
                                offset += chunk_len
                    except Exception as e:
                        continue

    def get_metadata(self) -> Dict[str, Any]:
        """
        Retrieves acquisition target metadata.
        """
        return {
            "target_path": os.path.abspath(self.target_path),
            "total_bytes": self.total_bytes,
            "block_size": self.block_size,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "is_directory": os.path.isdir(self.target_path) if os.path.exists(self.target_path) else False
        }
