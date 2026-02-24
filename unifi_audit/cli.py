from __future__ import annotations

import argparse
import pathlib
import sys

from .backup import BackupExtractionError, extract_backup
from .checks import run_checks
from .reporting import to_csv, to_html, to_json, to_text

AUDIT_COLLECTION_ALLOWLIST = {
    "admin",
    "user",
    "account",
    "wlanconf",
    "wlan",
    "wifi_network",
    "wireless_network",
    "networkconf",
    "network",
    "vlan",
    "lan_network",
    "device",
    "stat_device",
    "network_device",
    "gateway_device",
    "setting",
    "site",
    "system_settings",
    "network_settings",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unifi-backup-audit",
        description="Evaluate UniFi backup files for security and performance issues.",
    )
    parser.add_argument("backup", help="Path to UniFi backup file (.unf or .zip)")
    parser.add_argument(
        "--backup-password",
        default=None,
        help="Backup encryption password (for password-protected UniFi backups)",
    )
    parser.add_argument("--format", choices=["text", "json", "html", "csv"], default="text", help="Output format")
    parser.add_argument(
        "--profile",
        choices=["baseline", "cis-nist"],
        default="cis-nist",
        help="Policy profile for scoring and control mapping",
    )
    parser.add_argument("--output", help="Write report to file path instead of stdout")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if HIGH findings exist (CI gate)",
    )
    parser.add_argument(
        "--strict-score-min",
        type=int,
        default=None,
        help="Exit non-zero if overall score is below this value (0-100)",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep extracted temporary files for debugging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    backup_path = str(pathlib.Path(args.backup).expanduser())

    extracted = None
    try:
        from .parser import ParseError, load_collections
    except ModuleNotFoundError as exc:
        print(
            "ERROR: Missing dependency for BSON parsing. Install with: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2

    try:
        extracted = extract_backup(backup_path, backup_password=args.backup_password)
        collections = load_collections(extracted.extracted_dir, allowlist=AUDIT_COLLECTION_ALLOWLIST)
        report = run_checks(backup_path=backup_path, collections=collections, profile=args.profile)
    except (BackupExtractionError, ParseError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if extracted and not args.keep_temp:
            extracted.cleanup()

    if args.format == "json":
        rendered = to_json(report)
    elif args.format == "html":
        rendered = to_html(report)
    elif args.format == "csv":
        rendered = to_csv(report)
    else:
        rendered = to_text(report)
    if args.output:
        pathlib.Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    if args.strict_score_min is not None and not (0 <= args.strict_score_min <= 100):
        print("ERROR: --strict-score-min must be between 0 and 100.", file=sys.stderr)
        return 2

    has_high = any(f.severity.upper() == "HIGH" for f in report.findings)
    if args.strict and has_high:
        print("STRICT CHECK FAILED: one or more HIGH findings detected.", file=sys.stderr)
        return 3
    if args.strict_score_min is not None and report.score < args.strict_score_min:
        print(
            f"STRICT SCORE CHECK FAILED: score {report.score} is below minimum {args.strict_score_min}.",
            file=sys.stderr,
        )
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
