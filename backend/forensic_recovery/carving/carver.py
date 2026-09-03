import math
import os
import uuid
from typing import Any, Dict, List, Optional

from .signatures import DEFAULT_SIGNATURES, FileSignature
from ..acquisition.hashing import CryptographicHasher


class FileCarver:
    """
    Signature-based forensic file carver.

    Responsibilities:
        1. Scan binary evidence.
        2. Detect known file signatures.
        3. Determine probable file boundaries.
        4. Extract candidate artifacts.
        5. Calculate artifact hashes.
        6. Calculate entropy.
        7. Store recovered artifacts.
        8. Remove duplicate artifacts.

    Important:
        The original evidence file is never modified.
    """

    DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
    DEFAULT_OVERLAP = 128 * 1024

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
            exist_ok=True,
        )

    # ==============================================================
    # ENTROPY
    # ==============================================================

    @staticmethod
    def calculate_entropy(
        data: bytes,
    ) -> float:
        """
        Calculates Shannon entropy.

        Range:
            0.0 -> highly repetitive data
            8.0 -> maximum byte entropy

        Entropy is used as a supporting forensic indicator.
        It is NOT by itself proof that an artifact is valid.
        """

        if not data:
            return 0.0

        byte_counts = [0] * 256

        for byte in data:
            byte_counts[byte] += 1

        length = len(data)
        entropy = 0.0

        for count in byte_counts:
            if count == 0:
                continue

            probability = count / length

            entropy -= (
                probability
                * math.log2(probability)
            )

        return round(entropy, 3)

    # ==============================================================
    # FILE VALIDATION
    # ==============================================================

    @staticmethod
    def _basic_signature_validation(
        file_bytes: bytes,
        signature: FileSignature,
    ) -> bool:
        """
        Performs basic structural validation.

        Checks:
            - Minimum size
            - Correct header
            - Footer when available
        """

        if len(file_bytes) < signature.min_size:
            return False

        if not file_bytes.startswith(
            signature.header
        ):
            return False

        if (
            signature.footer
            and not file_bytes.endswith(
                signature.footer
            )
        ):
            return False

        return True

    # ==============================================================
    # ENTROPY CLASSIFICATION
    # ==============================================================

    @staticmethod
    def _classify_entropy(
        entropy: float,
    ) -> str:
        """
        Classifies entropy as a supporting integrity indicator.

        This is NOT a forensic authenticity determination.
        """

        if entropy < 1.0:
            return "Very Low"

        if entropy < 3.0:
            return "Low"

        if entropy < 6.5:
            return "Normal"

        if entropy < 7.8:
            return "High"

        return "Very High"

    # ==============================================================
    # CARVE BUFFER
    # ==============================================================

    def carve_buffer(
        self,
        buffer: bytes,
        start_offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Searches a binary buffer for known file signatures.

        Returns recovered artifact metadata.
        """

        carved_results: List[
            Dict[str, Any]
        ] = []

        buffer_length = len(buffer)

        if buffer_length == 0:
            return carved_results

        for signature in self.signatures:

            header_length = len(
                signature.header
            )

            search_position = 0

            while search_position < buffer_length:

                header_position = buffer.find(
                    signature.header,
                    search_position,
                )

                if header_position == -1:
                    break

                absolute_offset = (
                    start_offset
                    + header_position
                )

                carve_end = None

                # --------------------------------------------------
                # Footer-based carving
                # --------------------------------------------------

                if signature.footer:

                    footer_search_end = min(
                        buffer_length,
                        header_position
                        + signature.max_size,
                    )

                    footer_position = buffer.find(
                        signature.footer,
                        header_position
                        + header_length,
                        footer_search_end,
                    )

                    if footer_position != -1:

                        carve_end = (
                            footer_position
                            + len(signature.footer)
                        )

                # --------------------------------------------------
                # Size-based fallback
                # --------------------------------------------------

                if carve_end is None:

                    fallback_end = min(
                        buffer_length,
                        header_position
                        + signature.max_size,
                    )

                    carve_end = fallback_end

                file_bytes = buffer[
                    header_position:carve_end
                ]

                # --------------------------------------------------
                # Basic structural validation
                # --------------------------------------------------

                if not self._basic_signature_validation(
                    file_bytes,
                    signature,
                ):
                    search_position = (
                        header_position
                        + header_length
                    )
                    continue

                # --------------------------------------------------
                # Generate artifact identity
                # --------------------------------------------------

                artifact_id = (
                    f"ART-"
                    f"{uuid.uuid4().hex[:12].upper()}"
                )

                filename = (
                    f"{artifact_id}."
                    f"{signature.extension}"
                )

                file_path = os.path.join(
                    self.output_dir,
                    filename,
                )

                # --------------------------------------------------
                # Write recovered artifact
                # --------------------------------------------------

                try:

                    with open(
                        file_path,
                        "wb",
                    ) as recovered_file:

                        recovered_file.write(
                            file_bytes
                        )

                except OSError:

                    search_position = (
                        header_position
                        + header_length
                    )

                    continue

                # --------------------------------------------------
                # Calculate hashes
                # --------------------------------------------------

                hashes = (
                    CryptographicHasher
                    .calculate_bytes_hashes(
                        file_bytes
                    )
                )

                sha256 = hashes.get(
                    "sha256"
                )

                md5 = hashes.get(
                    "md5"
                )

                # --------------------------------------------------
                # Entropy
                # --------------------------------------------------

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

                # --------------------------------------------------
                # Artifact metadata
                # --------------------------------------------------

                artifact = {

                    "artifact_id": artifact_id,

                    "name": filename,

                    "type": signature.name,

                    "category": signature.category,

                    "extension": signature.extension,

                    "mime_type": signature.mime_type,

                    "offset": absolute_offset,

                    "source_offset": absolute_offset,

                    "size": len(file_bytes),

                    "sha256": sha256,

                    "md5": md5,

                    "entropy": entropy,

                    "entropy_class": entropy_class,

                    "recovery_method": (
                        "SIGNATURE_CARVING"
                    ),

                    "file_path": file_path,

                    "status": "RECOVERED",

                    "validation_status": (
                        "PENDING"
                    ),

                    "validationStatus": (
                        "PENDING"
                    ),
                }

                carved_results.append(
                    artifact
                )

                # --------------------------------------------------
                # Move search position forward
                # --------------------------------------------------

                search_position = (
                    header_position
                    + header_length
                )

        return carved_results

    # ==============================================================
    # CARVE FILE
    # ==============================================================

    def carve_file(
        self,
        target_path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> List[Dict[str, Any]]:
        """
        Sequentially scans an evidence file.

        Uses overlapping chunks so signatures crossing
        chunk boundaries can still be detected.
        """

        target_path = os.path.abspath(
            target_path
        )

        if not os.path.isfile(
            target_path
        ):
            raise FileNotFoundError(
                f"Target file for carving not found: "
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

        overlap = self.DEFAULT_OVERLAP

        previous_tail = b""

        with open(
            target_path,
            "rb",
        ) as evidence_file:

            offset = 0

            while offset < file_size:

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
                    offset
                    - len(previous_tail)
                )

                carved = self.carve_buffer(
                    full_buffer,
                    start_offset=buffer_start_offset,
                )

                results.extend(
                    carved
                )

                # Keep overlap for next chunk.
                if len(chunk) >= overlap:

                    previous_tail = (
                        chunk[-overlap:]
                    )

                else:

                    previous_tail = chunk

                offset += len(chunk)

        # ==========================================================
        # DEDUPLICATION
        # ==========================================================

        unique_results: Dict[
            str,
            Dict[str, Any]
        ] = {}

        for artifact in results:

            sha256 = artifact.get(
                "sha256",
                "",
            )

            offset_value = artifact.get(
                "source_offset",
                artifact.get(
                    "offset",
                    -1,
                ),
            )

            key = (
                f"{sha256}:"
                f"{offset_value}"
            )

            if key not in unique_results:

                unique_results[key] = (
                    artifact
                )

        return list(
            unique_results.values()
        )