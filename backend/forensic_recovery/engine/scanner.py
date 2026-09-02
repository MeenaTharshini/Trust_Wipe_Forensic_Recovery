import os
import sys
import time
import json
import uuid
from typing import Dict, Any, List, Callable, Optional
from ..acquisition.evidence import EvidenceAcquisition
from ..acquisition.hashing import CryptographicHasher
from ..carving.carver import FileCarver
from ..engine.metadata import MetadataExtractor
from ..reports.chain_of_custody import ChainOfCustody
from ..reports.report_generator import ReportGenerator

class ForensicScanner:
    """
    High-level orchestrator for full forensic recovery and acquisition scans.
    Executes drive/image inspection, carving, hashing, metadata extraction,
    and progress streaming.
    """
    def __init__(self, case_id: str, investigator: str, target_path: str, output_dir: str):
        self.job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        self.case_id = case_id
        self.investigator = investigator
        self.target_path = os.path.abspath(target_path)
        self.output_dir = os.path.abspath(output_dir)
        self.recovered_dir = os.path.join(self.output_dir, "recovered", self.job_id)
        os.makedirs(self.recovered_dir, exist_ok=True)

        self.chain_of_custody = ChainOfCustody(case_id=case_id, investigator=investigator)
        self.carver = FileCarver(output_dir=self.recovered_dir)
        
        self.status = "INITIALIZED"
        self.progress = 0.0
        self.bytes_scanned = 0
        self.total_bytes = 0
        self.carved_artifacts: List[Dict[str, Any]] = []

    def run_scan(self, progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """
        Runs full evidence acquisition, carving, and analysis pipeline.
        """
        self.status = "ACQUIRING"
        start_time = time.time()
        
        if not os.path.exists(self.target_path):
            self.status = "FAILED"
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")

        acq = EvidenceAcquisition(self.target_path)
        acq_meta = acq.get_metadata()
        self.total_bytes = acq_meta["total_bytes"] if acq_meta["total_bytes"] > 0 else 1048576

        self.chain_of_custody.add_entry(
            action="SCAN_STARTED",
            details=f"Target: {self.target_path}, Total Bytes: {self.total_bytes}",
            evidence_hash=CryptographicHasher.calculate_bytes_hashes(self.target_path.encode())["sha256"]
        )

        self.status = "CARVING"
        
        if os.path.isfile(self.target_path):
            carved_list = self.carver.carve_file(self.target_path)
            self.carved_artifacts.extend(carved_list)
            self.bytes_scanned = self.total_bytes
            self.progress = 100.0
        elif os.path.isdir(self.target_path):
            current_scanned = 0
            for root, _, files in os.walk(self.target_path):
                for f_name in files:
                    file_p = os.path.join(root, f_name)
                    f_size = os.path.getsize(file_p) if os.path.exists(file_p) else 0
                    try:
                        carved = self.carver.carve_file(file_p)
                        self.carved_artifacts.extend(carved)
                    except Exception:
                        pass
                    
                    current_scanned += f_size
                    self.bytes_scanned = current_scanned
                    self.progress = min(99.0, round((current_scanned / max(1, self.total_bytes)) * 100, 1))

                    if progress_callback:
                        progress_callback({
                            "job_id": self.job_id,
                            "status": self.status,
                            "progress": self.progress,
                            "bytes_scanned": self.bytes_scanned,
                            "total_bytes": self.total_bytes,
                            "carved_count": len(self.carved_artifacts)
                        })

        # Enrich metadata for carved files
        for artifact in self.carved_artifacts:
            file_meta = MetadataExtractor.extract_file_metadata(artifact["file_path"])
            artifact["metadata"] = file_meta

        self.progress = 100.0
        self.status = "COMPLETED"
        elapsed_sec = round(time.time() - start_time, 2)

        self.chain_of_custody.add_entry(
            action="SCAN_COMPLETED",
            details=f"Recovered {len(self.carved_artifacts)} artifacts in {elapsed_sec} seconds.",
            evidence_hash=CryptographicHasher.calculate_bytes_hashes(f"{self.job_id}_{len(self.carved_artifacts)}".encode())["sha256"]
        )

        # Generate output reports
        report_gen = ReportGenerator(
            job_id=self.job_id,
            case_id=self.case_id,
            investigator=self.investigator,
            target_path=self.target_path,
            carved_artifacts=self.carved_artifacts,
            chain_of_custody=self.chain_of_custody.get_log()
        )
        report_data = report_gen.generate_json_report(os.path.join(self.output_dir, f"report_{self.job_id}.json"))

        final_summary = {
            "job_id": self.job_id,
            "case_id": self.case_id,
            "investigator": self.investigator,
            "target_path": self.target_path,
            "status": self.status,
            "progress": 100.0,
            "bytes_scanned": self.bytes_scanned,
            "total_bytes": self.total_bytes,
            "carved_count": len(self.carved_artifacts),
            "carved_artifacts": self.carved_artifacts,
            "chain_of_custody": self.chain_of_custody.get_log(),
            "elapsed_seconds": elapsed_sec,
            "report_path": os.path.join(self.output_dir, f"report_{self.job_id}.json")
        }

        if progress_callback:
            progress_callback(final_summary)

        return final_summary
