from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from .acquisition.evidence import acquire_evidence
from .engine.scanner import scan_evidence
from .reports.chain_of_custody import ChainOfCustody


class ForensicService:

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)

    def create_case(
        self,
        case_id: str,
        examiner: str,
        source: str,
    ) -> dict[str, Any]:

        case_dir = self.workspace / "cases" / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        return {
            "case_id": case_id,
            "examiner": examiner,
            "source": source,
            "created_at": time.time(),
            "status": "CREATED",
        }

    def analyze(
        self,
        case_id: str,
        source: str | Path,
        examiner: str,
    ) -> dict[str, Any]:

        operation_id = f"FORENSIC-{uuid.uuid4().hex[:16]}"

        case_dir = (
            self.workspace
            / "cases"
            / case_id
        )

        case_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        custody = ChainOfCustody(
            case_dir / "chain_of_custody.jsonl"
        )

        custody.record(
            action="CASE_STARTED",
            case_id=case_id,
            examiner=examiner,
            operation_id=operation_id,
            source=str(source),
        )

        started = time.time()

        try:

            evidence = acquire_evidence(
                source
            )

            custody.record(
                action="EVIDENCE_ACQUIRED",
                case_id=case_id,
                examiner=examiner,
                operation_id=operation_id,
                evidence=evidence,
            )

            result = scan_evidence(
                evidence_path=Path(
                    evidence["path"]
                ),
                output_directory=(
                    case_dir / "recovered"
                ),
            )

            custody.record(
                action="ANALYSIS_COMPLETED",
                case_id=case_id,
                examiner=examiner,
                operation_id=operation_id,
                result={
                    "artifacts":
                        result.get(
                            "artifacts_carved",
                            0,
                        ),
                },
            )

            duration = (
                time.time() - started
            )

            return {
                "success": True,
                "operation_id":
                    operation_id,
                "case_id":
                    case_id,
                "evidence":
                    evidence,
                "analysis":
                    result,
                "duration_ms":
                    round(duration * 1000),
                "status":
                    "COMPLETED",
            }

        except Exception as exc:

            custody.record(
                action="ANALYSIS_FAILED",
                case_id=case_id,
                examiner=examiner,
                operation_id=operation_id,
                error=str(exc),
            )

            return {
                "success": False,
                "operation_id":
                    operation_id,
                "case_id":
                    case_id,
                "status":
                    "FAILED",
                "error":
                    str(exc),
            }