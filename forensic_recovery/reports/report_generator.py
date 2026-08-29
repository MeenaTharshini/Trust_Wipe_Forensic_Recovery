import json
from pathlib import Path
from datetime import datetime, timezone
from forensic_recovery.acquisition.evidence import identify

def generate_report(case_id: str, examiner: str, evidence_path: Path, output_path: Path):
    evidence = identify(evidence_path)
    report = {
        "schema": "forensic-recovery-report/v1",
        "case_id": case_id,
        "examiner": examiner,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "evidence": evidence.to_dict(),
        "analysis": {
            "mode": "read-only",
            "scope": "authorized forensic analysis",
            "notes": "Starter report. Add filesystem and recovery findings after analysis."
        }
    }
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
