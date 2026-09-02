import time
import uuid
from typing import List, Dict, Any

class ChainOfCustody:
    """
    Maintains an audit trail of evidence acquisition, analysis,
    hashing, and file extraction activities for court admissibility.
    """
    def __init__(self, case_id: str, investigator: str):
        self.case_id = case_id
        self.investigator = investigator
        self.log: List[Dict[str, Any]] = []
        self._add_system_entry("CASE_INITIALIZED", f"Case {case_id} registered by investigator {investigator}")

    def add_entry(self, action: str, details: str, evidence_hash: str) -> Dict[str, Any]:
        """
        Adds a cryptographic verification entry to the chain of custody.
        """
        entry = {
            "entry_id": f"COC-{uuid.uuid4().hex[:6].upper()}",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "case_id": self.case_id,
            "investigator": self.investigator,
            "action": action,
            "details": details,
            "evidence_hash": evidence_hash
        }
        self.log.append(entry)
        return entry

    def _add_system_entry(self, action: str, details: str):
        self.log.append({
            "entry_id": f"COC-SYS-{uuid.uuid4().hex[:6].upper()}",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "case_id": self.case_id,
            "investigator": self.investigator,
            "action": action,
            "details": details,
            "evidence_hash": "N/A_SYSTEM_INIT"
        })

    def get_log(self) -> List[Dict[str, Any]]:
        return self.log
