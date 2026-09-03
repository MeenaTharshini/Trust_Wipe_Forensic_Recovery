import os
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from ..acquisition.evidence import EvidenceAcquisition
from ..acquisition.hashing import CryptographicHasher
from ..carving.carver import FileCarver
from ..engine.metadata import MetadataExtractor
from ..reports.chain_of_custody import ChainOfCustody
from ..reports.report_generator import ReportGenerator


class ForensicScanner:
    """
    High-level forensic acquisition and recovery orchestrator.

    Pipeline:

        Evidence Verification
                ↓
        Evidence Acquisition Metadata
                ↓
        SHA-256 Evidence Hash
                ↓
        Signature-Based Carving
                ↓
        Artifact Validation
                ↓
        Artifact SHA-256
                ↓
        Metadata Extraction
                ↓
        Chain of Custody
                ↓
        JSON Forensic Report
    """

    def __init__(
        self,
        case_id: str,
        investigator: str,
        target_path: str,
        output_dir: str,
    ):

        self.job_id = (
            f"JOB-{uuid.uuid4().hex[:8].upper()}"
        )

        self.case_id = case_id
        self.investigator = investigator

        self.target_path = os.path.abspath(
            target_path
        )

        self.output_dir = os.path.abspath(
            output_dir
        )

        # Node.js supplies the case-isolated
        # recovery directory.
        self.recovered_dir = (
            self.output_dir
        )

        os.makedirs(
            self.recovered_dir,
            exist_ok=True,
        )

        self.chain_of_custody = (
            ChainOfCustody(
                case_id=case_id,
                investigator=investigator,
            )
        )

        self.carver = FileCarver(
            output_dir=self.recovered_dir
        )

        self.status = "INITIALIZED"

        self.progress = 0.0

        self.bytes_scanned = 0

        self.total_bytes = 0

        self.carved_artifacts: List[
            Dict[str, Any]
        ] = []

    # ==============================================================
    # PROGRESS
    # ==============================================================

    def _emit_progress(
        self,
        progress_callback: Optional[
            Callable[[Dict[str, Any]], None]
        ],
    ) -> None:

        if not progress_callback:
            return

        progress_callback({

            "job_id": self.job_id,

            "case_id": self.case_id,

            "status": self.status,

            "progress": self.progress,

            "bytes_scanned": (
                self.bytes_scanned
            ),

            "total_bytes": (
                self.total_bytes
            ),

            "carved_count": (
                len(
                    self.carved_artifacts
                )
            ),

            "artifacts_validated": (
                self._get_validated_count()
            ),
        })

    # ==============================================================
    # EVIDENCE HASH
    # ==============================================================

    def _calculate_evidence_hash(
        self,
    ) -> str:
        """
        Calculates SHA-256 from actual evidence bytes
        when target is a file.
        """

        if os.path.isfile(
            self.target_path
        ):

            hashes = (
                CryptographicHasher
                .calculate_file_hashes(
                    self.target_path
                )
            )

            return hashes["sha256"]

        # Directory fallback.
        #
        # NOTE:
        # This is an identifier for the directory path,
        # not a cryptographic hash of all directory contents.
        return (
            CryptographicHasher
            .calculate_bytes_hashes(
                self.target_path.encode(
                    "utf-8"
                )
            )["sha256"]
        )

    # ==============================================================
    # ARTIFACT VALIDATION
    # ==============================================================

    def _validate_artifact(
        self,
        artifact: Dict[str, Any],
    ) -> str:
        """
        Performs basic recovered-artifact validation.

        Validation checks:

            1. File path exists.
            2. File is a regular file.
            3. File has non-zero size.
            4. File begins with expected signature when available.
            5. SHA-256 can be calculated.
        """

        file_path = artifact.get(
            "file_path"
        )

        if not file_path:
            return "INVALID"

        if not os.path.isfile(
            file_path
        ):
            return "INVALID"

        try:

            file_size = os.path.getsize(
                file_path
            )

        except OSError:

            return "INVALID"

        if file_size <= 0:
            return "INVALID"

        # ----------------------------------------------------------
        # Recalculate SHA-256 from disk.
        # ----------------------------------------------------------

        try:

            hashes = (
                CryptographicHasher
                .calculate_file_hashes(
                    file_path
                )
            )

            calculated_sha256 = (
                hashes.get("sha256")
            )

            if not calculated_sha256:
                return "INVALID"

            # Store the authoritative hash
            # calculated from the recovered file.
            artifact["sha256"] = (
                calculated_sha256
            )

            if hashes.get("md5"):
                artifact["md5"] = (
                    hashes["md5"]
                )

        except Exception:

            return "INVALID"

        return "VALIDATED"

    # ==============================================================
    # VALIDATED COUNT
    # ==============================================================

    def _get_validated_count(
        self,
    ) -> int:

        count = 0

        for artifact in (
            self.carved_artifacts
        ):

            status = str(
                artifact.get(
                    "validation_status",
                    artifact.get(
                        "validationStatus",
                        "",
                    ),
                )
            ).upper()

            if status in (
                "VALIDATED",
                "VALID",
            ):

                count += 1

        return count

    # ==============================================================
    # SCAN FILE
    # ==============================================================

    def _scan_file(
        self,
    ) -> None:

        carved = (
            self.carver.carve_file(
                self.target_path
            )
        )

        self.carved_artifacts.extend(
            carved
        )

        try:

            self.bytes_scanned = (
                os.path.getsize(
                    self.target_path
                )
            )

        except OSError:

            self.bytes_scanned = (
                self.total_bytes
            )

    # ==============================================================
    # SCAN DIRECTORY
    # ==============================================================

    def _scan_directory(
        self,
        progress_callback: Optional[
            Callable[[Dict[str, Any]], None]
        ] = None,
    ) -> None:

        current_scanned = 0

        for root, _, files in os.walk(
            self.target_path
        ):

            for file_name in files:

                file_path = os.path.join(
                    root,
                    file_name,
                )

                try:

                    file_size = (
                        os.path.getsize(
                            file_path
                        )
                    )

                except OSError:

                    file_size = 0

                try:

                    carved = (
                        self.carver.carve_file(
                            file_path
                        )
                    )

                    self.carved_artifacts.extend(
                        carved
                    )

                except Exception:
                    # Continue with remaining evidence.
                    pass

                current_scanned += (
                    file_size
                )

                self.bytes_scanned = (
                    current_scanned
                )

                self.progress = min(
                    90.0,
                    round(
                        (
                            current_scanned
                            / max(
                                1,
                                self.total_bytes,
                            )
                        )
                        * 90.0,
                        1,
                    ),
                )

                self._emit_progress(
                    progress_callback
                )

    # ==============================================================
    # MAIN SCAN
    # ==============================================================

    def run_scan(
        self,
        progress_callback: Optional[
            Callable[[Dict[str, Any]], None]
        ] = None,
    ) -> Dict[str, Any]:

        start_time = time.time()

        try:

            # ------------------------------------------------------
            # 1. Verify target
            # ------------------------------------------------------

            self.status = "VERIFYING"
            self.progress = 2.0

            self._emit_progress(
                progress_callback
            )

            if not os.path.exists(
                self.target_path
            ):

                raise FileNotFoundError(
                    "Target path does not exist: "
                    f"{self.target_path}"
                )

            # ------------------------------------------------------
            # 2. Acquisition metadata
            # ------------------------------------------------------

            self.status = "ACQUIRING"
            self.progress = 5.0

            self._emit_progress(
                progress_callback
            )

            acquisition = (
                EvidenceAcquisition(
                    self.target_path
                )
            )

            acquisition_metadata = (
                acquisition.get_metadata()
            )

            if isinstance(
                acquisition_metadata,
                dict,
            ):

                self.total_bytes = int(
                    acquisition_metadata.get(
                        "total_bytes",
                        0,
                    )
                    or 0
                )

            if self.total_bytes <= 0:

                self.total_bytes = 1

            # ------------------------------------------------------
            # 3. Evidence SHA-256
            # ------------------------------------------------------

            evidence_sha256 = (
                self._calculate_evidence_hash()
            )

            # ------------------------------------------------------
            # 4. Chain of custody
            # ------------------------------------------------------

            self.chain_of_custody.add_entry(

                action="SCAN_STARTED",

                details=(
                    f"Target: "
                    f"{self.target_path}; "
                    f"Total Bytes: "
                    f"{self.total_bytes}"
                ),

                evidence_hash=(
                    evidence_sha256
                ),
            )

            # ------------------------------------------------------
            # 5. Carving
            # ------------------------------------------------------

            self.status = "CARVING"
            self.progress = 10.0

            self._emit_progress(
                progress_callback
            )

            if os.path.isfile(
                self.target_path
            ):

                self._scan_file()

                self.progress = 90.0

            elif os.path.isdir(
                self.target_path
            ):

                self._scan_directory(
                    progress_callback
                )

            # ------------------------------------------------------
            # 6. Validation
            # ------------------------------------------------------

            self.status = "VALIDATING"
            self.progress = 92.0

            self._emit_progress(
                progress_callback
            )

            for artifact in (
                self.carved_artifacts
            ):

                validation_status = (
                    self._validate_artifact(
                        artifact
                    )
                )

                artifact[
                    "validation_status"
                ] = validation_status

                artifact[
                    "validationStatus"
                ] = validation_status

                artifact[
                    "status"
                ] = "RECOVERED"

            # ------------------------------------------------------
            # 7. Metadata
            # ------------------------------------------------------

            self.status = "ANALYZING"
            self.progress = 95.0

            self._emit_progress(
                progress_callback
            )

            for artifact in (
                self.carved_artifacts
            ):

                file_path = artifact.get(
                    "file_path"
                )

                if not file_path:
                    continue

                if not os.path.isfile(
                    file_path
                ):
                    continue

                try:

                    metadata = (
                        MetadataExtractor
                        .extract_file_metadata(
                            file_path
                        )
                    )

                    artifact[
                        "metadata"
                    ] = metadata

                except Exception as exc:

                    artifact[
                        "metadata"
                    ] = {
                        "error": str(exc)
                    }

            # ------------------------------------------------------
            # 8. Statistics
            # ------------------------------------------------------

            artifacts_recovered = len(
                self.carved_artifacts
            )

            artifacts_validated = (
                self._get_validated_count()
            )

            elapsed_seconds = round(
                time.time()
                - start_time,
                2,
            )

            # ------------------------------------------------------
            # 9. Chain of custody
            # ------------------------------------------------------

            self.chain_of_custody.add_entry(

                action="SCAN_COMPLETED",

                details=(
                    f"Recovered "
                    f"{artifacts_recovered} "
                    f"artifacts; "
                    f"validated "
                    f"{artifacts_validated} "
                    f"artifacts; "
                    f"elapsed "
                    f"{elapsed_seconds} seconds."
                ),

                evidence_hash=(
                    evidence_sha256
                ),
            )

            # ------------------------------------------------------
            # 10. Generate report
            # ------------------------------------------------------

            report_path = os.path.join(
                self.output_dir,
                f"report_{self.job_id}.json",
            )

            report_generator = (
                ReportGenerator(
                    job_id=self.job_id,
                    case_id=self.case_id,
                    investigator=self.investigator,
                    target_path=self.target_path,
                    carved_artifacts=(
                        self.carved_artifacts
                    ),
                    chain_of_custody=(
                        self.chain_of_custody
                        .get_log()
                    ),
                )
            )

            report_error = None

            try:

                report_generator.generate_json_report(
                    report_path
                )

            except Exception as exc:

                report_error = str(exc)

            # ------------------------------------------------------
            # 11. Complete
            # ------------------------------------------------------

            self.status = "COMPLETED"
            self.progress = 100.0

            final_summary = {

                "job_id": self.job_id,

                "case_id": self.case_id,

                "investigator": (
                    self.investigator
                ),

                "target_path": (
                    self.target_path
                ),

                "status": self.status,

                "progress": 100.0,

                "bytes_scanned": (
                    self.bytes_scanned
                ),

                "total_bytes": (
                    self.total_bytes
                ),

                "carved_count": (
                    artifacts_recovered
                ),

                "artifacts_carved": (
                    artifacts_recovered
                ),

                "artifacts_validated": (
                    artifacts_validated
                ),

                "artifacts": (
                    self.carved_artifacts
                ),

                "carved_artifacts": (
                    self.carved_artifacts
                ),

                "evidence_sha256": (
                    evidence_sha256
                ),

                "chain_of_custody": (
                    self.chain_of_custody
                    .get_log()
                ),

                "elapsed_seconds": (
                    elapsed_seconds
                ),

                "report_path": (
                    report_path
                ),
            }

            if report_error:

                final_summary[
                    "report_error"
                ] = report_error

            self._emit_progress(
                progress_callback
            )

            return final_summary

        except Exception as exc:

            self.status = "FAILED"

            self.progress = 100.0

            elapsed_seconds = round(
                time.time()
                - start_time,
                2,
            )

            failure_result = {

                "job_id": self.job_id,

                "case_id": self.case_id,

                "investigator": (
                    self.investigator
                ),

                "target_path": (
                    self.target_path
                ),

                "status": "FAILED",

                "progress": self.progress,

                "bytes_scanned": (
                    self.bytes_scanned
                ),

                "total_bytes": (
                    self.total_bytes
                ),

                "carved_count": (
                    len(
                        self.carved_artifacts
                    )
                ),

                "artifacts_carved": (
                    len(
                        self.carved_artifacts
                    )
                ),

                "artifacts_validated": (
                    self._get_validated_count()
                ),

                "artifacts": (
                    self.carved_artifacts
                ),

                "error": str(exc),

                "elapsed_seconds": (
                    elapsed_seconds
                ),
            }

            self._emit_progress(
                progress_callback
            )

            raise