#!/usr/bin/env python3
import os
import sys
import argparse
import json
import string
import ctypes
from typing import List, Dict, Any

# Adjust module imports
# ---------------------------------------------------------------------------
# PACKAGE IMPORT CONFIGURATION
# ---------------------------------------------------------------------------

FORENSIC_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.dirname(FORENSIC_ROOT)

if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from forensic_recovery.engine.scanner import ForensicScanner
from forensic_recovery.acquisition.hashing import CryptographicHasher
def get_available_drives() -> List[Dict[str, Any]]:
    """
    Lists system drives and available storage mount points.
    """
    drives = []
    if sys.platform.startswith('win'):
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drive_path = f"{letter}:\\"
                try:
                    free_bytes = ctypes.c_ulonglong()
                    total_bytes = ctypes.c_ulonglong()
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        ctypes.c_wchar_p(drive_path),
                        None,
                        ctypes.byref(total_bytes),
                        ctypes.byref(free_bytes)
                    )
                    drives.append({
                        "id": f"drive_{letter}",
                        "name": f"Logical Drive ({letter}:)",
                        "path": drive_path,
                        "total_gb": round(total_bytes.value / (1024**3), 2),
                        "free_gb": round(free_bytes.value / (1024**3), 2),
                        "type": "Fixed Disk"
                    })
                except Exception:
                    drives.append({
                        "id": f"drive_{letter}",
                        "name": f"Drive ({letter}:)",
                        "path": drive_path,
                        "total_gb": 0,
                        "free_gb": 0,
                        "type": "Storage Volume"
                    })
            bitmask >>= 1
    else:
        # Linux/macOS fallback
        drives.append({
            "id": "root_vol",
            "name": "Root Volume (/)",
            "path": "/",
            "total_gb": 256.0,
            "free_gb": 128.0,
            "type": "System Volume"
        })

    # Always include evidence sample dir if available
    sample_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "evidence"))
    os.makedirs(sample_dir, exist_ok=True)
    drives.append({
        "id": "evidence_dir",
        "name": "Forensic Evidence Vault",
        "path": sample_dir,
        "total_gb": 50.0,
        "free_gb": 50.0,
        "type": "Evidence Folder"
    })
    
    return drives

def main():
    parser = argparse.ArgumentParser(description="TrustWipe Commercial Forensic Recovery CLI Engine")
    parser.add_argument("--list-drives", action="store_true", help="List available local drives and evidence storage target locations")
    parser.add_argument("--scan", action="store_true", help="Execute full forensic analysis scan & carving")
    parser.add_argument("--target", type=str, default="", help="Target drive or evidence file/folder path")
    parser.add_argument("--output", type=str, default="./reports", help="Output directory for reports and carved files")
    parser.add_argument("--case", type=str, default="CASE-2026-001", help="Case reference ID")
    parser.add_argument("--investigator", type=str, default="Lead Forensic Officer", help="Investigator name")
    parser.add_argument("--json", action="store_true", help="Format stdout as JSON events")

    args = parser.parse_args()

    if args.list_drives:
        drives = get_available_drives()
        if args.json:
            print(json.dumps({"status": "SUCCESS", "drives": drives}))
        else:
            print("Available Forensic Targets:")
            for d in drives:
                print(f" - {d['name']} [{d['path']}] ({d['total_gb']} GB total)")
        return

    if args.scan:
        if not args.target:
            sample_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "evidence"))
            os.makedirs(sample_dir, exist_ok=True)
            args.target = sample_dir

        output_dir = os.path.abspath(args.output)
        scanner = ForensicScanner(
            case_id=args.case,
            investigator=args.investigator,
            target_path=args.target,
            output_dir=output_dir
        )

        def emit_progress(evt):
            if args.json:
                print(json.dumps({"type": "PROGRESS", "data": evt}), flush=True)

        results = scanner.run_scan(progress_callback=emit_progress)

        if args.json:
            print(json.dumps({"type": "COMPLETED", "data": results}), flush=True)
        else:
            print(f"\n[+] Forensic Scan Completed. Job ID: {results['job_id']}")
            print(f"[+] Recovered Artifacts: {results['carved_count']}")
            print(f"[+] Report saved to: {results['report_path']}")

if __name__ == "__main__":
    main()
