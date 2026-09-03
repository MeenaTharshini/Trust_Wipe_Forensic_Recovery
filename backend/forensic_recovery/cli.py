
#!/usr/bin/env python3

import os
import sys
import argparse
import json
import string
import ctypes
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# PACKAGE IMPORT CONFIGURATION
# ---------------------------------------------------------------------------

FORENSIC_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.dirname(FORENSIC_ROOT)

if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from forensic_recovery.engine.scanner import ForensicScanner
from forensic_recovery.acquisition.hashing import CryptographicHasher


# ---------------------------------------------------------------------------
# AVAILABLE DRIVES
# ---------------------------------------------------------------------------

def get_available_drives() -> List[Dict[str, Any]]:
    """
    Lists system drives and available storage mount points.
    """

    drives = []

    if sys.platform.startswith("win"):

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
                        "total_gb": round(
                            total_bytes.value / (1024 ** 3), 2
                        ),
                        "free_gb": round(
                            free_bytes.value / (1024 ** 3), 2
                        ),
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

        # Linux / macOS fallback
        drives.append({
            "id": "root_vol",
            "name": "Root Volume (/)",
            "path": "/",
            "total_gb": 256.0,
            "free_gb": 128.0,
            "type": "System Volume"
        })

    # -----------------------------------------------------------------------
    # FORENSIC EVIDENCE DIRECTORY
    # -----------------------------------------------------------------------

    sample_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "evidence")
    )

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


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="TrustWipe Commercial Forensic Recovery CLI Engine"
    )

    # Optional positional command.
    # This allows:
    # python cli.py scan
    parser.add_argument(
        "command",
        nargs="?",
        choices=["scan"],
        help="Forensic command to execute"
    )

    # List drives
    parser.add_argument(
        "--list-drives",
        action="store_true",
        help="List available local drives and evidence storage targets"
    )

    # Scan flag
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Execute full forensic analysis scan and carving"
    )

    # Target / Input
    # Supports BOTH:
    # --target
    # --input
    parser.add_argument(
        "--target",
        "--input",
        dest="target",
        type=str,
        default="",
        help="Target drive, evidence file, or evidence folder"
    )

    # Output directory
    parser.add_argument(
        "--output",
        type=str,
        default="./reports",
        help="Output directory for reports and recovered artifacts"
    )

    # Case ID
    parser.add_argument(
        "--case",
        type=str,
        default="CASE-2026-001",
        help="Case reference ID"
    )

    # Investigator / Examiner
    # Supports BOTH:
    # --investigator
    # --examiner
    parser.add_argument(
        "--investigator",
        "--examiner",
        dest="investigator",
        type=str,
        default="Lead Forensic Officer",
        help="Investigator / examiner name"
    )

    # JSON output
    parser.add_argument(
        "--json",
        action="store_true",
        help="Return a single JSON result"
    )

    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # LIST DRIVES
    # -----------------------------------------------------------------------

    if args.list_drives:

        drives = get_available_drives()

        if args.json:

            print(
                json.dumps({
                    "status": "SUCCESS",
                    "drives": drives
                }),
                flush=True
            )

        else:

            print("Available Forensic Targets:")

            for drive in drives:
                print(
                    f" - {drive['name']} "
                    f"[{drive['path']}] "
                    f"({drive['total_gb']} GB total)"
                )

        return

    # -----------------------------------------------------------------------
    # DETERMINE WHETHER SCAN WAS REQUESTED
    # -----------------------------------------------------------------------

    scan_requested = (
        args.scan
        or args.command == "scan"
        or bool(args.target)
    )

    if scan_requested:

        # ---------------------------------------------------------------
        # DEFAULT TARGET
        # ---------------------------------------------------------------

        if not args.target:

            sample_dir = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    "evidence"
                )
            )

            os.makedirs(sample_dir, exist_ok=True)

            args.target = sample_dir

        # ---------------------------------------------------------------
        # VALIDATE TARGET
        # ---------------------------------------------------------------

        if not os.path.exists(args.target):

            error_result = {
                "status": "FAILED",
                "error": {
                    "code": "TARGET_NOT_FOUND",
                    "message": f"Target does not exist: {args.target}"
                }
            }

            if args.json:
                print(
                    json.dumps(error_result),
                    flush=True
                )
            else:
                print(
                    f"[ERROR] Target does not exist: {args.target}"
                )

            sys.exit(1)

        # ---------------------------------------------------------------
        # OUTPUT DIRECTORY
        # ---------------------------------------------------------------

        output_dir = os.path.abspath(args.output)

        os.makedirs(output_dir, exist_ok=True)

        # ---------------------------------------------------------------
        # CREATE FORENSIC SCANNER
        # ---------------------------------------------------------------

        scanner = ForensicScanner(
            case_id=args.case,
            investigator=args.investigator,
            target_path=args.target,
            output_dir=output_dir
        )

        # ---------------------------------------------------------------
        # PROGRESS CALLBACK
        # ---------------------------------------------------------------
        #
        # IMPORTANT:
        # Node.js expects one JSON object from stdout.
        # Therefore, DO NOT print progress JSON when --json is enabled.
        #

        def emit_progress(evt):

            if not args.json:

                progress = evt.get("progress", 0)
                scanned = evt.get("bytes_scanned", 0)
                recovered = evt.get("carved_count", 0)

                print(
                    f"Progress: {progress}% | "
                    f"Scanned: {scanned} bytes | "
                    f"Recovered: {recovered}",
                    flush=True
                )

        # ---------------------------------------------------------------
        # RUN SCAN
        # ---------------------------------------------------------------

        try:

            results = scanner.run_scan(
                progress_callback=emit_progress
            )

        except Exception as exc:

            error_result = {
                "status": "FAILED",
                "error": {
                    "code": "FORENSIC_SCAN_FAILED",
                    "message": str(exc)
                }
            }

            if args.json:

                # Only ONE JSON object is printed.
                print(
                    json.dumps(error_result),
                    flush=True
                )

            else:

                print(
                    f"[ERROR] Forensic scan failed: {exc}"
                )

            sys.exit(1)

        # ---------------------------------------------------------------
        # JSON RESULT
        # ---------------------------------------------------------------

        if args.json:

            # IMPORTANT:
            # Print exactly ONE JSON object.
            print(
                json.dumps(results, default=str),
                flush=True
            )

        # ---------------------------------------------------------------
        # NORMAL TERMINAL RESULT
        # ---------------------------------------------------------------

        else:

            print(
                "\n[+] Forensic Scan Completed."
            )

            print(
                f"[+] Job ID: "
                f"{results.get('job_id', 'N/A')}"
            )

            print(
                f"[+] Recovered Artifacts: "
                f"{results.get('carved_count', 0)}"
            )

            print(
                f"[+] Report saved to: "
                f"{results.get('report_path', 'N/A')}"
            )

        return

    # -----------------------------------------------------------------------
    # NO COMMAND
    # -----------------------------------------------------------------------

    parser.print_help()


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
