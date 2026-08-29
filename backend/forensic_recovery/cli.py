"""
TrustWipe Forensic Recovery Engine
==================================

Command-line interface for the TrustWipe forensic recovery engine.

Supported commands:

    hash
        Calculate SHA-256.

    acquire
        Create an acquisition record.

    scan
        Scan evidence and recover artifacts.

    report
        Generate a forensic report.

The Express backend invokes:

    python cli.py scan \
        --input <evidence> \
        --output <recovered> \
        --case <case-id> \
        --examiner <examiner> \
        --json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any


# ============================================================================
# PATH BOOTSTRAP
# ============================================================================

CURRENT_FILE = Path(__file__).resolve()

FORENSIC_ROOT = CURRENT_FILE.parent

BACKEND_ROOT = FORENSIC_ROOT.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(BACKEND_ROOT),
    )


# ============================================================================
# FORENSIC ENGINE IMPORTS
# ============================================================================

try:
    from forensic_recovery.acquisition.evidence import (
        EvidenceAcquisitionError,
        identify,
    )

    from forensic_recovery.acquisition.hashing import (
        HashingError,
        sha256_file,
    )

    from forensic_recovery.engine.scanner import (
        ScannerError,
        ScannerInputError,
        ScannerLimitError,
        ScannerReadError,
        scan_image,
    )

    from forensic_recovery.reports.report_generator import (
        generate_report,
    )

except ImportError as exc:
    print(
        "ERROR: Unable to load TrustWipe forensic modules.",
        file=sys.stderr,
    )

    print(
        f"Import error: {exc}",
        file=sys.stderr,
    )

    print(
        f"Forensic root: {FORENSIC_ROOT}",
        file=sys.stderr,
    )

    print(
        f"Backend root: {BACKEND_ROOT}",
        file=sys.stderr,
    )

    sys.exit(2)


# ============================================================================
# APPLICATION METADATA
# ============================================================================

APP_NAME = (
    "TrustWipe Forensic Recovery Engine"
)

APP_VERSION = "2.1.0"


# ============================================================================
# LOGGING
# ============================================================================

logger = logging.getLogger(
    "trustwipe.forensics"
)


def configure_logging(
    verbose: bool = False,
) -> None:
    """
    Configure logging.

    IMPORTANT:
    When --json is used, logging goes to stderr
    so stdout remains machine-readable JSON.
    """

    level = (
        logging.DEBUG
        if verbose
        else logging.INFO
    )

    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


# ============================================================================
# ARGUMENT VALIDATORS
# ============================================================================

def positive_integer(
    value: str,
) -> int:
    try:
        number = int(value)

    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid integer: {value}"
        ) from exc

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "Value must be greater than zero."
        )

    return number


def existing_file(
    value: str,
) -> Path:
    """
    Validate that an evidence file exists.
    """

    path = (
        Path(value)
        .expanduser()
        .resolve()
    )

    if not path.exists():
        raise argparse.ArgumentTypeError(
            f"File does not exist: {path}"
        )

    if path.is_symlink():
        raise argparse.ArgumentTypeError(
            f"Symbolic links are not accepted: {path}"
        )

    if not path.is_file():
        raise argparse.ArgumentTypeError(
            f"Path is not a regular file: {path}"
        )

    return path


def directory_path(
    value: str,
) -> Path:
    return (
        Path(value)
        .expanduser()
        .resolve()
    )


# ============================================================================
# JSON HELPERS
# ============================================================================

def write_json(
    data: Any,
    output_path: Path,
) -> None:

    output_path = (
        Path(output_path)
        .expanduser()
        .resolve()
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = (
        output_path.with_name(
            output_path.name + ".tmp"
        )
    )

    try:
        with temporary_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as file:

            json.dump(
                data,
                file,
                indent=2,
                ensure_ascii=False,
            )

            file.write("\n")

        temporary_path.replace(
            output_path
        )

    except OSError:

        try:
            temporary_path.unlink(
                missing_ok=True
            )
        except OSError:
            pass

        raise


def print_json(
    data: Any,
) -> None:

    print(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
    )


# ============================================================================
# HASH
# ============================================================================

def command_hash(
    args: argparse.Namespace,
) -> int:

    evidence_path: Path = args.input

    logger.info(
        "Calculating SHA-256: %s",
        evidence_path,
    )

    digest = sha256_file(
        evidence_path,
        chunk_size=args.chunk_size,
    )

    result = {
        "operation": "hash",
        "algorithm": "SHA-256",
        "path": str(
            evidence_path.resolve()
        ),
        "size":
            evidence_path.stat().st_size,
        "sha256":
            digest,
    }

    if args.json:
        print_json(result)
        return 0

    print()
    print("TrustWipe SHA-256")
    print("=================")
    print(
        f"File:       {evidence_path}"
    )
    print(
        f"Size:       {result['size']} bytes"
    )
    print(
        f"SHA-256:    {digest}"
    )
    print()

    return 0


# ============================================================================
# ACQUIRE
# ============================================================================

def command_acquire(
    args: argparse.Namespace,
) -> int:

    evidence_path: Path = args.input

    logger.info(
        "Acquiring evidence: %s",
        evidence_path,
    )

    evidence =
        identify(evidence_path)

    result = evidence.to_dict()

    if args.output:
        write_json(
            result,
            args.output,
        )

    if args.json:
        print_json(result)
        return 0

    print()
    print("TrustWipe Evidence Acquisition")
    print("===============================")

    print(
        f"Path:        {result.get('path', evidence_path)}"
    )

    print(
        f"Size:        {result.get('size', 0)} bytes"
    )

    print(
        f"SHA-256:     {result.get('sha256', '')}"
    )

    print(
        f"Algorithm:   {result.get('hash_algorithm', 'SHA-256')}"
    )

    print(
        f"Acquired:    {result.get('acquired_utc', '')}"
    )

    if args.output:
        print(
            f"Record:      {args.output}"
        )

    print()

    return 0


# ============================================================================
# SCAN
# ============================================================================

def command_scan(
    args: argparse.Namespace,
) -> int:
    """
    Run the actual forensic scanner.

    The scanner performs:

        Evidence
           ↓
        Streaming scan
           ↓
        Signature detection
           ↓
        Candidate ranges
           ↓
        Range carving
           ↓
        Validation
           ↓
        Artifact hashing
    """

    evidence_path: Path = args.input

    output_dir: Path = (
        args.output
        .expanduser()
        .resolve()
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    logger.info(
        "TrustWipe forensic scan started."
    )

    logger.info(
        "Evidence: %s",
        evidence_path,
    )

    logger.info(
        "Output: %s",
        output_dir,
    )

    logger.info(
        "Case: %s",
        args.case or "N/A",
    )

    logger.info(
        "Examiner: %s",
        args.examiner or "N/A",
    )

    logger.info(
        "Chunk size: %d bytes",
        args.chunk_size,
    )

    # ------------------------------------------------------------------------
    # RUN SCANNER
    # ------------------------------------------------------------------------

    result = scan_image(
        image_path=evidence_path,
        output_dir=output_dir,
        chunk_size=args.chunk_size,
    )

    if result is None:
        result = {}

    if not isinstance(
        result,
        dict,
    ):
        result = {
            "scanner_result":
                result
        }

    # ------------------------------------------------------------------------
    # NORMALIZE CORE FIELDS
    # ------------------------------------------------------------------------

    result.setdefault(
        "operation",
        "scan",
    )

    result.setdefault(
        "evidence_path",
        str(evidence_path),
    )

    result.setdefault(
        "evidence_size",
        evidence_path.stat().st_size,
    )

    result.setdefault(
        "chunk_size",
        args.chunk_size,
    )

    result.setdefault(
        "status",
        "COMPLETED",
    )

    # ------------------------------------------------------------------------
    # CASE INFORMATION
    # ------------------------------------------------------------------------

    if args.case:
        result["case_id"] = args.case

    if args.examiner:
        result["examiner"] = (
            args.examiner
        )

    # ------------------------------------------------------------------------
    # NORMALIZE COUNTS
    # ------------------------------------------------------------------------

    result.setdefault(
        "signatures_detected",
        result.get(
            "signaturesDetected",
            0,
        ),
    )

    result.setdefault(
        "candidates_found",
        result.get(
            "candidatesFound",
            result.get(
                "candidate_count",
                0,
            ),
        ),
    )

    result.setdefault(
        "artifacts_carved",
        result.get(
            "artifactsCarved",
            0,
        ),
    )

    result.setdefault(
        "artifacts_validated",
        result.get(
            "artifactsValidated",
            len(
                result.get(
                    "artifacts",
                    [],
                )
            ),
        ),
    )

    # ------------------------------------------------------------------------
    # NORMALIZE ARTIFACTS
    # ------------------------------------------------------------------------

    artifacts = result.get(
        "artifacts",
        [],
    )

    if not isinstance(
        artifacts,
        list,
    ):
        artifacts = []

    normalized_artifacts = []

    for index, artifact in enumerate(
        artifacts,
        start=1,
    ):

        if not isinstance(
            artifact,
            dict,
        ):
            continue

        normalized = dict(
            artifact
        )

        normalized.setdefault(
            "artifact_id",
            f"ART-{index:05d}",
        )

        normalized.setdefault(
            "size",
            0,
        )

        normalized.setdefault(
            "validation",
            normalized.get(
                "valid",
                "UNKNOWN",
            ),
        )

        normalized.setdefault(
            "sha256",
            normalized.get(
                "artifact_sha256"
            ),
        )

        normalized_artifacts.append(
            normalized
        )

    result["artifacts"] = (
        normalized_artifacts
    )

    result["artifacts_validated"] = (
        max(
            int(
                result.get(
                    "artifacts_validated",
                    0,
                )
            ),
            len(
                normalized_artifacts
            ),
        )
    )

    # ------------------------------------------------------------------------
    # OUTPUT RESULT JSON
    # ------------------------------------------------------------------------

    if args.result:

        result_path = (
            args.result
            .expanduser()
            .resolve()
        )

        write_json(
            result,
            result_path,
        )

        logger.info(
            "Scan result written to: %s",
            result_path,
        )

    # ------------------------------------------------------------------------
    # JSON OUTPUT
    # ------------------------------------------------------------------------

    if args.json:
        print_json(result)
        return 0

    # ------------------------------------------------------------------------
    # HUMAN OUTPUT
    # ------------------------------------------------------------------------

    print()
    print("TrustWipe Forensic Scan")
    print("=======================")

    print(
        f"Evidence:             {result.get('evidence_path')}"
    )

    print(
        f"Evidence size:        {result.get('evidence_size', 0)} bytes"
    )

    print(
        f"Chunk size:           {result.get('chunk_size', 0)} bytes"
    )

    print(
        f"Overlap:              {result.get('overlap_size', 0)} bytes"
    )

    print(
        f"Signatures detected:  {result.get('signatures_detected', 0)}"
    )

    print(
        f"Candidates found:     {result.get('candidates_found', 0)}"
    )

    print(
        f"Artifacts carved:     {result.get('artifacts_carved', 0)}"
    )

    print(
        f"Artifacts validated:  {result.get('artifacts_validated', 0)}"
    )

    print(
        f"Status:               {result.get('status', 'UNKNOWN')}"
    )

    if args.case:
        print(
            f"Case ID:              {args.case}"
        )

    if args.examiner:
        print(
            f"Examiner:             {args.examiner}"
        )

    print(
        f"Recovery directory:   {output_dir}"
    )

    print()

    if normalized_artifacts:

        print("Recovered Artifacts")
        print("-------------------")

        for index, artifact in enumerate(
            normalized_artifacts,
            start=1,
        ):

            print(
                f"{index}. "
                f"{artifact.get('artifact_id')}"
            )

            print(
                f"   Type:       "
                f"{artifact.get('type', 'UNKNOWN')}"
            )

            print(
                f"   Size:       "
                f"{artifact.get('size', 0)} bytes"
            )

            print(
                f"   Offset:     "
                f"{artifact.get('offset', artifact.get('source_offset', 0))}"
            )

            print(
                f"   Validation: "
                f"{artifact.get('validation', 'UNKNOWN')}"
            )

            if artifact.get(
                "sha256"
            ):
                print(
                    f"   SHA-256:    "
                    f"{artifact['sha256']}"
                )

            if artifact.get(
                "output"
            ):
                print(
                    f"   Output:     "
                    f"{artifact['output']}"
                )

            print()

    else:
        print(
            "No validated artifacts recovered."
        )

    return 0


# ============================================================================
# REPORT
# ============================================================================

def command_report(
    args: argparse.Namespace,
) -> int:

    logger.info(
        "Generating report for case: %s",
        args.case,
    )

    input_path = (
        args.input
        .expanduser()
        .resolve()
    )

    output_path = (
        args.output
        .expanduser()
        .resolve()
    )

    if not input_path.exists():
        raise FileNotFoundError(
            f"Report input does not exist: {input_path}"
        )

    report = generate_report(
        args.case,
        args.examiner,
        input_path,
        output_path,
    )

    if args.json:
        print_json(
            report
        )
        return 0

    print()
    print("TrustWipe Forensic Report")
    print("=========================")

    print(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )
    )

    print()

    print(
        f"Report written to: {output_path}"
    )

    return 0


# ============================================================================
# ARGUMENT PARSER
# ============================================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="trustwipe-forensics",
        description=(
            "TrustWipe Authorized Digital "
            "Forensics Recovery Engine"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"%(prog)s {APP_VERSION}"
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Enable diagnostic logging."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print command results as JSON."
        ),
    )

    subparsers = (
        parser.add_subparsers(
            dest="command",
            required=True,
        )
    )

    # ------------------------------------------------------------------------
    # HASH
    # ------------------------------------------------------------------------

    hash_parser = (
        subparsers.add_parser(
            "hash",
            help=(
                "Calculate SHA-256."
            ),
        )
    )

    hash_parser.add_argument(
        "input",
        type=existing_file,
        help="Evidence file.",
    )

    hash_parser.add_argument(
        "--chunk-size",
        type=positive_integer,
        default=1024 * 1024,
        help=(
            "Hash chunk size."
        ),
    )

    hash_parser.set_defaults(
        handler=command_hash
    )

    # ------------------------------------------------------------------------
    # ACQUIRE
    # ------------------------------------------------------------------------

    acquire_parser = (
        subparsers.add_parser(
            "acquire",
            help=(
                "Create acquisition record."
            ),
        )
    )

    acquire_parser.add_argument(
        "input",
        type=existing_file,
        help="Evidence file.",
    )

    acquire_parser.add_argument(
        "--output",
        type=Path,
        help="Acquisition JSON output.",
    )

    acquire_parser.set_defaults(
        handler=command_acquire
    )

    # ------------------------------------------------------------------------
    # SCAN
    # ------------------------------------------------------------------------

    scan_parser = (
        subparsers.add_parser(
            "scan",
            help=(
                "Scan and recover forensic artifacts."
            ),
        )
    )

    scan_parser.add_argument(
        "input",
        nargs="?",
        type=existing_file,
        help="Evidence file.",
    )

    scan_parser.add_argument(
        "--input",
        dest="input_option",
        type=existing_file,
        help=(
            "Evidence file. Used by the Express backend."
        ),
    )

    scan_parser.add_argument(
        "--output",
        type=directory_path,
        default=(
            FORENSIC_ROOT /
            "recovered"
        ),
        help=(
            "Recovered artifact directory."
        ),
    )

    scan_parser.add_argument(
        "--result",
        type=Path,
        default=None,
        help=(
            "Optional scan-result JSON."
        ),
    )

    scan_parser.add_argument(
        "--chunk-size",
        type=positive_integer,
        default=64 * 1024 * 1024,
        help=(
            "Scanner chunk size in bytes."
        ),
    )

    scan_parser.add_argument(
        "--case",
        default=None,
        help="Forensic case ID.",
    )

    scan_parser.add_argument(
        "--examiner",
        default=None,
        help="Examiner name.",
    )

    scan_parser.set_defaults(
        handler=command_scan
    )

    # ------------------------------------------------------------------------
    # REPORT
    # ------------------------------------------------------------------------

    report_parser = (
        subparsers.add_parser(
            "report",
            help=(
                "Generate forensic report."
            ),
        )
    )

    report_parser.add_argument(
        "--case",
        required=True,
        help="Case ID.",
    )

    report_parser.add_argument(
        "--examiner",
        required=True,
        help="Examiner.",
    )

    report_parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input report data.",
    )

    report_parser.add_argument(
        "--output",
        type=Path,
        default=(
            FORENSIC_ROOT /
            "report.json"
        ),
        help="Output report.",
    )

    report_parser.set_defaults(
        handler=command_report
    )

    return parser


# ============================================================================
# NORMALIZE SCAN INPUT
# ============================================================================

def normalize_scan_input(
    args: argparse.Namespace,
) -> None:

    positional =
        getattr(
            args,
            "input",
            None,
        )

    optional =
        getattr(
            args,
            "input_option",
            None,
        )

    if (
        positional is not None
        and optional is not None
    ):
        raise ValueError(
            "Specify the evidence input only once."
        )

    resolved =
        optional or positional

    if resolved is None:
        raise ValueError(
            "Evidence input is required. "
            "Use: scan <file> or "
            "scan --input <file>."
        )

    args.input = resolved

    if hasattr(
        args,
        "input_option",
    ):
        delattr(
            args,
            "input_option",
        )


# ============================================================================
# MAIN
# ============================================================================

def main(
    argv: list[str] | None = None,
) -> int:

    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    configure_logging(
        verbose=args.verbose
    )

    if args.command == "scan":
        try:
            normalize_scan_input(
                args
            )
        except ValueError as exc:
            parser.error(
                str(exc)
            )

    try:
        return args.handler(
            args
        )

    except (
        HashingError,
        EvidenceAcquisitionError,
        ScannerInputError,
        ScannerLimitError,
        ScannerReadError,
        ScannerError,
        OSError,
        ValueError,
        FileNotFoundError,
    ) as exc:

        logger.error(
            "%s",
            exc,
        )

        return 1

    except KeyboardInterrupt:

        logger.error(
            "Operation cancelled."
        )

        return 130

    except Exception:

        logger.exception(
            "Unexpected forensic engine failure."
        )

        return 2


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    sys.exit(
        main()
    )