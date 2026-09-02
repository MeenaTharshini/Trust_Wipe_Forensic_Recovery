import os
import uuid
import math
from typing import List, Dict, Any, Optional, Tuple
from .signatures import DEFAULT_SIGNATURES, FileSignature
from ..acquisition.hashing import CryptographicHasher

class FileCarver:
    """
    Real signature-based file carver.
    Scans binary data or disk images, detects file headers/footers,
    extracts fragments, validates entropy, and outputs recovered files.
    """
    def __init__(self, output_dir: str, signatures: Optional[List[FileSignature]] = None):
        self.output_dir = os.path.abspath(output_dir)
        self.signatures = signatures if signatures else DEFAULT_SIGNATURES
        os.makedirs(self.output_dir, exist_ok=True)

    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculates Shannon Entropy of a byte buffer (0.0 - 8.0).
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def carve_buffer(self, buffer: bytes, start_offset: int = 0) -> List[Dict[str, Any]]:
        """
        Scans an in-memory byte buffer for signature matches and carves embedded files.
        """
        carved_results = []
        buf_len = len(buffer)
        
        for sig in self.signatures:
            hdr_len = len(sig.header)
            pos = 0
            
            while pos < buf_len:
                # Find next occurrence of header
                pos = buffer.find(sig.header, pos)
                if pos == -1:
                    break
                
                header_offset = start_offset + pos
                carve_end = -1
                
                if sig.footer:
                    ftr_len = len(sig.footer)
                    search_end = min(buf_len, pos + sig.max_size)
                    ftr_pos = buffer.find(sig.footer, pos + hdr_len, search_end)
                    if ftr_pos != -1:
                        carve_end = ftr_pos + ftr_len
                
                if carve_end == -1:
                    # Heuristic size fallback if no footer found or defined
                    carve_end = min(buf_len, pos + min(1048576, sig.max_size))
                
                file_bytes = buffer[pos:carve_end]
                if len(file_bytes) >= hdr_len + 4:
                    file_id = f"CARVED_{uuid.uuid4().hex[:8].upper()}"
                    filename = f"{file_id}.{sig.extension}"
                    filepath = os.path.join(self.output_dir, filename)
                    
                    with open(filepath, 'wb') as f:
                        f.write(file_bytes)
                    
                    hashes = CryptographicHasher.calculate_bytes_hashes(file_bytes)
                    entropy = self.calculate_entropy(file_bytes)
                    
                    carved_results.append({
                        "id": file_id,
                        "name": filename,
                        "type": sig.name,
                        "category": sig.category,
                        "extension": sig.extension,
                        "offset": header_offset,
                        "size": len(file_bytes),
                        "sha256": hashes["sha256"],
                        "md5": hashes["md5"],
                        "entropy": entropy,
                        "file_path": filepath,
                        "status": "Recovered",
                        "integrity": "High" if entropy > 3.0 and entropy < 7.9 else "Moderate"
                    })
                    
                # Advance search position past header
                pos += hdr_len

        return carved_results

    def carve_file(self, target_path: str, chunk_size: int = 4194304) -> List[Dict[str, Any]]:
        """
        Scans a disk image or evidence file sequentially using sliding chunk buffers.
        """
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target file for carving not found: {target_path}")

        results = []
        file_size = os.path.getsize(target_path)
        
        with open(target_path, 'rb') as f:
            offset = 0
            overlap = 65536  # Overlap buffer to catch signatures across chunk boundaries
            prev_tail = b""
            
            while offset < file_size:
                f.seek(offset)
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                full_buf = prev_tail + chunk
                buf_start_offset = max(0, offset - len(prev_tail))
                
                carved_in_chunk = self.carve_buffer(full_buf, start_offset=buf_start_offset)
                results.extend(carved_in_chunk)
                
                prev_tail = chunk[-overlap:] if len(chunk) >= overlap else chunk
                offset += len(chunk)

        # De-duplicate results with identical hashes/offsets
        unique_results = {}
        for r in results:
            key = f"{r['sha256']}_{r['offset']}"
            if key not in unique_results:
                unique_results[key] = r

        return list(unique_results.values())
