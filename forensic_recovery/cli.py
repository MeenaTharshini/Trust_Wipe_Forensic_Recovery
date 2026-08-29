"""
TrustWipe Forensic Recovery Engine
==================================

Command-line interface for authorized forensic evidence processing.

Supported operations:

    hash
        Calculate SHA-256 for an evidence file.

    acquire
        Create an evidence acquisition record containing the
        cryptographic baseline.

    scan
        Stream-scan an evidence image and recover candidate
        artifacts using range-based carving.

    report
        Generate a JSON forensic case report.

Examples:

    python -m forensic_recovery.cli hash evidence/test.img

    python -m forensic_recovery.cli acquire evidence/test.img

    python -m forensic_recovery.cli acquire evidence/test.img \
        --output evidence.json

    python -m forensic_recovery.cli scan evidence/test.img \
        --output recovered/

    python -m forensic_recovery.cli scan evidence/test.img \
        --output recovered/ \
        --case CASE-2026-03 \
        --examiner "Meena Tharshini I"

    python -m forensic_recovery.cli scan \
        --input evidence/test.img \
        --output recovered/

    python -m forensic_recovery.cli report \
        --case CASE-2026-03 \
        --examiner "Meena Tharshini I" \
        --input evidence.json \
        --output reports/report.json
"""

from __future__ import annotations

# ============================================================================
# BOOTSTRAP
# ============================================================================

import sys
from pathlib import Path


CURRENT_FILE = Path(__file__).resolve()

FORENSIC_PACKAGE_DIR = CURRENT_FILE.parent
PROJECT_ROOT = FORENSIC_PACKAGE_DIR.parent


if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================================
# STANDARD LIBRARY
# ============================================================================

import argparse
import json
import logging
from typing import Any


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

except ImportError as import_error:

    print(
        "ERROR: Unable to load TrustWipe forensic modules.",
        file=sys.stderr,
    )

    print(
        f"Import error: {import_error}",
        file=sys.stderr,
    )

    print(
        f"Forensic package: {FORENSIC_PACKAGE_DIR}",
        file=sys.stderr,
    )

    print(
        f"Project root: {PROJECT_ROOT}",
        file=sys.stderr,
    )

    sys.exit(2)


# ============================================================================
# APPLICATION METADATA
# ============================================================================

APP_NAME = "TrustWipe Forensic Recovery Engine"
APP_VERSION = "2.0.0"


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
    Configure CLI logging.

    Normal operation:
        INFO

    Verbose operation:
        DEBUG
    """

    level = (
        logging.DEBUG
        if verbose
        else logging.INFO
    )

    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


# ============================================================================
# ARGUMENT VALIDATORS
# ============================================================================

def positive_integer(
    value: str,
) -> int:
    """
    argparse validator for positive integers.
    """

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
    argparse validator for an existing regular file.

    Symbolic links are rejected because forensic evidence
    should resolve to a specific immutable source.
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
    """
    Convert an output directory argument to an absolute Path.

    The directory does not have to exist yet.
    """

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
    """
    Safely write JSON.

    A temporary file is written first and then atomically
    replaced into the requested destination.
    """

    output_path = (
        Path(output_path)
        .expanduser()
        .resolve()
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = output_path.with_name(
        output_path.name + ".tmp"
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
    """
    Print structured JSON to stdout.
    """

    print(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
    )


# ============================================================================
# HASH COMMAND
# ============================================================================

def command_hash(
    args: argparse.Namespace,
) -> int:
    """
    Calculate SHA-256 for an evidence file.
    """

    path: Path = args.input

    logger.info(
        "Calculating SHA-256: %s",
        path,
    )

    digest = sha256_file(
        path,
        chunk_size=args.chunk_size,
    )

    result = {
        "operation": "hash",
        "algorithm": "SHA-256",
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": digest,
    }

    if args.json:

        print_json(result)

    else:

        print()
        print("TrustWipe SHA-256")
        print("-----------------")
        print(f"File:              {path}")
        print(f"Size:              {result['size']} bytes")
        print(f"SHA-256:           {digest}")
        print()

    return 0


# ============================================================================
# ACQUIRE COMMAND
# ============================================================================

def command_acquire(
    args: argparse.Namespace,
) -> int:
    """
    Create a cryptographic evidence acquisition record.
    """

    path: Path = args.input

    logger.info(
        "Acquiring evidence: %s",
        path,
    )

    evidence = identify(path)

    result = evidence.to_dict()

    if args.output:

        output_path: Path = (
            args.output
            .expanduser()
            .resolve()
        )

        write_json(
            result,
            output_path,
        )

        logger.info(
            "Evidence record written to: %s",
            output_path,
        )

    if args.json:

        print_json(result)

    else:

        print()
        print("Evidence Acquisition")
        print("--------------------")

        print(
            f"Path:             "
            f"{result.get('path', path)}"
        )

        print(
            f"Size:             "
            f"{result.get('size', 0)} bytes"
        )

        print(
            f"SHA-256:          "
            f"{result.get('sha256', '')}"
        )

        print(
            f"Algorithm:        "
            f"{result.get('hash_algorithm', 'SHA-256')}"
        )

        print(
            f"Acquired UTC:     "
            f"{result.get('acquired_utc', '')}"
        )

        print(
            f"Schema Version:   "
            f"{result.get('schema_version', '1.0')}"
        )

        if args.output:

            print(
                f"Record:           "
                f"{args.output.resolve()}"
            )

        print()

    return 0


# ============================================================================
# SCAN COMMAND
# ============================================================================

def command_scan(
    args: argparse.Namespace,
) -> int:
    """
    Stream-scan an evidence image and recover candidate artifacts.

    IMPORTANT:

    The CLI does not load the evidence image into memory.

    scan_image() performs:

        Evidence
            ↓
        Streaming signature detection
            ↓
        Absolute offsets
            ↓
        Range-based carving
            ↓
        Artifact validation
            ↓
        Artifact hashes
    """

    image_path: Path = args.input

    output_dir: Path = (
        args.output
        .expanduser()
        .resolve()
    )

    logger.info(
        "Starting forensic scan: %s",
        image_path,
    )

    logger.info(
        "Recovery directory: %s",
        output_dir,
    )

    logger.info(
        "Scanner chunk size: %d bytes",
        args.chunk_size,
    )

    # ---------------------------------------------------------------
    # The scanner itself creates the output directory.
    #
    # Do not read the evidence file here.
    # ---------------------------------------------------------------

    result = scan_image(
        image_path=image_path,
        output_dir=output_dir,
        chunk_size=args.chunk_size,
    )

    # ---------------------------------------------------------------
    # Add CLI investigation context without changing the scanner's
    # core forensic result.
    # ---------------------------------------------------------------

    if args.case is not None:

        result["case_id"] = args.case

    if args.examiner is not None:

        result["examiner"] = args.examiner

    # ---------------------------------------------------------------
    # Optional scan-result JSON
    # ---------------------------------------------------------------

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

    # ---------------------------------------------------------------
    # JSON mode
    # ---------------------------------------------------------------

    if args.json:

        print_json(result)

        return 0

    # ---------------------------------------------------------------
    # Human-readable mode
    # ---------------------------------------------------------------

    print()
    print("TrustWipe Forensic Scan")
    print("=======================")

    print(
        f"Evidence:          "
        f"{result.get('evidence_path', image_path)}"
    )

    print(
        f"Evidence size:     "
        f"{result.get('evidence_size', 0)} bytes"
    )

    print(
        f"Chunk size:        "
        f"{result.get('chunk_size', args.chunk_size)} bytes"
    )

    print(
        f"Overlap:            "
        f"{result.get('overlap_size', 0)} bytes"
    )

    print(
        f"Signatures found:  "
        f"{result.get('signatures_detected', 0)}"
    )

    print(
        f"Artifacts carved:  "
        f"{result.get('artifacts_carved', 0)}"
    )

    print(
        f"Status:            "
        f"{result.get('status', 'UNKNOWN')}"
    )

    if args.case:

        print(
            f"Case ID:           "
            f"{args.case}"
        )

    if args.examiner:

        print(
            f"Examiner:          "
            f"{args.examiner}"
        )

    print(
        f"Recovery directory:"
        f" {output_dir}"
    )

    if args.result:

        print(
            f"Result JSON:       "
            f"{args.result.resolve()}"
        )

    # ---------------------------------------------------------------
    # Recovered artifacts
    # ---------------------------------------------------------------

    artifacts = result.get(
        "artifacts",
        [],
    )

    print()

    if artifacts:

        print("Recovered Artifacts")
        print("-------------------")

        for index, artifact in enumerate(
            artifacts,
            start=1,
        ):

            artifact_id = artifact.get(
                "artifact_id",
                f"ARTIFACT-{index:05d}",
            )

            artifact_type = artifact.get(
                "type",
                artifact.get(
                    "format",
                    "UNKNOWN",
                ),
            )

            size = artifact.get(
                "size",
                0,
            )

            offset = artifact.get(
                "offset",
                artifact.get(
                    "source_offset",
                    0,
                ),
            )

            output = artifact.get(
                "output",
                artifact.get(
                    "output_path",
                    "",
                ),
            )

            validation = artifact.get(
                "validation",
                artifact.get(
                    "valid",
                    "UNKNOWN",
                ),
            )

            sha256 = artifact.get(
                "sha256",
                artifact.get(
                    "artifact_sha256",
                    "",
                ),
            )

            print(
                f"{index}. "
                f"{artifact_id}"
            )

            print(
                f"   Type:       {artifact_type}"
            )

            print(
                f"   Size:       {size} bytes"
            )

            print(
                f"   Offset:     {offset}"
            )

            print(
                f"   Validation: {validation}"
            )

            if sha256:

                print(
                    f"   SHA-256:    {sha256}"
                )

            if output:

                print(
                    f"   Output:     {output}"
                )

            print()

    else:

        print(
            "No recovered artifacts."
        )

        print(
            "No supported and recoverable "
            "file signatures were found."
        )

        print()

    return 0


# ============================================================================
# REPORT COMMAND
# ============================================================================

def command_report(
    args: argparse.Namespace,
) -> int:
    """
    Generate a forensic JSON case report.
    """

    logger.info(
        "Generating forensic report for case: %s",
        args.case,
    )

    input_path = (
        Path(args.input)
        .expanduser()
        .resolve()
    )

    output_path = (
        Path(args.output)
        .expanduser()
        .resolve()
    )

    if not input_path.exists():

        raise FileNotFoundError(
            f"Report input does not exist: "
            f"{input_path}"
        )

    report = generate_report(
        args.case,
        args.examiner,
        input_path,
        output_path,
    )

    if report is not None:

        if args.json:

            print_json(report)

        else:

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

    logger.info(
        "Report written to: %s",
        output_path,
    )

    if not args.json:

        print(
            f"Report written to "
            f"{output_path}"
        )

    return 0


# ============================================================================
# ARGUMENT PARSER
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """
    Build the TrustWipe forensic CLI.
    """

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

    # ========================================================================
    # HASH
    # ========================================================================

    hash_parser = subparsers.add_parser(
        "hash",
        help=(
            "Calculate SHA-256 for "
            "an evidence file."
        ),
    )

    hash_parser.add_argument(
        "input",
        type=existing_file,
        help="Path to evidence file.",
    )

    hash_parser.add_argument(
        "--chunk-size",
        type=positive_integer,
        default=1024 * 1024,
        help=(
            "Hashing chunk size in bytes "
            "(default: 1048576)."
        ),
    )

    hash_parser.set_defaults(
        handler=command_hash
    )

    # ========================================================================
    # ACQUIRE
    # ========================================================================

    acquire_parser = subparsers.add_parser(
        "acquire",
        help=(
            "Create a forensic evidence "
            "acquisition record."
        ),
    )

    acquire_parser.add_argument(
        "input",
        type=existing_file,
        help="Path to evidence file.",
    )

    acquire_parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Write acquisition metadata "
            "to a JSON file."
        ),
    )

    acquire_parser.set_defaults(
        handler=command_acquire
    )

    # ========================================================================
    # SCAN
    # ========================================================================

    scan_parser = subparsers.add_parser(
        "scan",
        help=(
            "Stream-scan a forensic image "
            "and recover candidate artifacts."
        ),
    )

    # Positional input:
    #
    #     scan evidence/test.img
    #
    scan_parser.add_argument(
        "input",
        type=existing_file,
        nargs="?",
        help=(
            "Path to forensic evidence image."
        ),
    )

    # Optional input:
    #
    #     scan --input evidence/test.img
    #
    # This is useful for your Node/Express backend.
    scan_parser.add_argument(
        "--input",
        dest="input_option",
        type=existing_file,
        help=(
            "Path to forensic evidence image."
        ),
    )

    scan_parser.add_argument(
        "--output",
        type=directory_path,
        default=Path("recovered").resolve(),
        help=(
            "Directory for recovered artifacts "
            "(default: recovered)."
        ),
    )

    scan_parser.add_argument(
        "--result",
        type=Path,
        default=None,
        help=(
            "Optional JSON file containing "
            "the complete scan result."
        ),
    )

    scan_parser.add_argument(
        "--chunk-size",
        type=positive_integer,
        default=64 * 1024 * 1024,
        help=(
            "Streaming scanner chunk size in bytes "
            "(default: 67108864 / 64 MiB)."
        ),
    )

    scan_parser.add_argument(
        "--case",
        default=None,
        help=(
            "Forensic case identifier."
        ),
    )

    scan_parser.add_argument(
        "--examiner",
        default=None,
        help=(
            "Name or identifier of examiner."
        ),
    )

    scan_parser.set_defaults(
        handler=command_scan
    )

    # ========================================================================
    # REPORT
    # ========================================================================

    report_parser = subparsers.add_parser(
        "report",
        help=(
            "Generate a forensic JSON case report."
        ),
    )

    report_parser.add_argument(
        "--case",
        required=True,
        help=(
            "Forensic case identifier."
        ),
    )

    report_parser.add_argument(
        "--examiner",
        required=True,
        help=(
            "Name or identifier of examiner."
        ),
    )

    report_parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help=(
            "Input evidence/report data."
        ),
    )

    report_parser.add_argument(
        "--output",
        type=Path,
        default=Path("report.json"),
        help=(
            "Output report path "
            "(default: report.json)."
        ),
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
    """
    Support both:

        scan evidence/test.img

    and:

        scan --input evidence/test.img

    The latter is useful when the Express backend
    launches the forensic engine.
    """

    positional_input = getattr(
        args,
        "input",
        None,
    )

    option_input = getattr(
        args,
        "input_option",
        None,
    )

    if (
        positional_input is not None
        and option_input is not None
    ):

        raise ValueError(
            "Specify the evidence input only once."
        )

    resolved_input = (
        option_input
        or positional_input
    )

    if resolved_input is None:

        raise ValueError(
            "Evidence input is required. "
            "Use: scan <file> or "
            "scan --input <file>."
        )

    args.input = resolved_input

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
    """
    CLI application entry point.

    Returns:
        Process exit code.
    """

    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    configure_logging(
        verbose=args.verbose
    )

    # ------------------------------------------------------------------------
    # Normalize scan arguments.
    # ------------------------------------------------------------------------

    if args.command == "scan":

        try:

            normalize_scan_input(
                args
            )

        except ValueError as exc:

            parser.error(
                str(exc)
            )

    # ------------------------------------------------------------------------
    # Execute command.
    # ------------------------------------------------------------------------

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
            "Operation cancelled by user."
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