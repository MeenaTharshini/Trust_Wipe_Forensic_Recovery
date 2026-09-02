import os
import json
import time
from typing import List, Dict, Any

class ReportGenerator:
    """
    Generates structured forensic summary reports in JSON and Markdown formats.
    """
    def __init__(self, job_id: str, case_id: str, investigator: str, target_path: str, carved_artifacts: List[Dict[str, Any]], chain_of_custody: List[Dict[str, Any]]):
        self.job_id = job_id
        self.case_id = case_id
        self.investigator = investigator
        self.target_path = target_path
        self.carved_artifacts = carved_artifacts
        self.chain_of_custody = chain_of_custody

    def generate_json_report(self, output_path: str) -> Dict[str, Any]:
        """
        Exports full forensic report to a JSON file.
        """
        report_data = {
            "report_metadata": {
                "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "job_id": self.job_id,
                "case_id": self.case_id,
                "investigator": self.investigator,
                "engine_version": "TrustWipe Forensic Engine 2.4"
            },
            "evidence_target": {
                "path": self.target_path,
                "total_recovered_artifacts": len(self.carved_artifacts)
            },
            "summary_by_category": self._get_category_breakdown(),
            "carved_artifacts": self.carved_artifacts,
            "chain_of_custody": self.chain_of_custody
        }

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

        return report_data

    def _get_category_breakdown(self) -> Dict[str, int]:
        counts = {}
        for art in self.carved_artifacts:
            cat = art.get("category", "Uncategorized")
            counts[cat] = counts.get(cat, 0) + 1
        return counts
