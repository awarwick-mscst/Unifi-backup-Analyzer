from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import zipfile
from typing import Any

from .backup import BackupExtractionError, extract_backup

SENSITIVE_KEYWORDS = {
    "password",
    "passphrase",
    "secret",
    "token",
    "key",
    "private",
    "hash",
    "salt",
    "x_auth",
}

PII_KEYS = {"name", "username", "email", "mac", "macaddr", "ip", "hostname", "dns", "site"}


def _stable_hash(value: str) -> str:
    return "h_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _mask_ip(value: str) -> str:
    if "." in value:
        parts = value.split(".")
        if len(parts) == 4:
            return ".".join(parts[:2] + ["x", "x"])
    if ":" in value:
        parts = value.split(":")
        return ":".join(parts[:3] + ["xxxx"])
    return _stable_hash(value)


def _sanitize_scalar(key: str, value: Any) -> Any:
    k = key.lower()
    if isinstance(value, str):
        if any(word in k for word in SENSITIVE_KEYWORDS):
            return "<redacted-secret>"
        if "@" in value and ("email" in k or re.match(r"^[^@]+@[^@]+$", value)):
            return "<redacted-email>"
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            return _mask_ip(value)
        if re.match(r"^[0-9a-fA-F]{2}([:\-][0-9a-fA-F]{2}){5}$", value):
            return "<redacted-mac>"
        if k in PII_KEYS:
            return _stable_hash(value)
    if isinstance(value, (bytes, bytearray)):
        return "<redacted-bytes>"
    return value


def sanitize_obj(obj: Any, parent_key: str = "") -> Any:
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for key, value in obj.items():
            key_str = str(key)
            lowered = key_str.lower()
            if any(word in lowered for word in SENSITIVE_KEYWORDS):
                cleaned[key_str] = "<redacted-secret>"
                continue
            cleaned[key_str] = sanitize_obj(_sanitize_scalar(key_str, value), key_str)
        return cleaned
    if isinstance(obj, list):
        return [sanitize_obj(item, parent_key) for item in obj]
    return _sanitize_scalar(parent_key, obj)


def _zip_dir(source_dir: pathlib.Path, output_zip: pathlib.Path) -> None:
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in source_dir.rglob("*"):
            if path.is_file():
                zf.write(path, arcname=path.relative_to(source_dir))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unifi-backup-sanitize",
        description="Sanitize a UniFi backup for safer sharing.",
    )
    parser.add_argument("backup", help="Path to UniFi backup file (.unf or .zip)")
    parser.add_argument(
        "--backup-password",
        default=None,
        help="Backup encryption password (for password-protected UniFi backups)",
    )
    parser.add_argument(
        "--mode",
        choices=["json", "backup"],
        default="backup",
        help="json: emit sanitized JSON snapshot, backup: emit sanitized backup zip",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path. Defaults to sanitized-backup.zip for backup mode, sanitized-backup.json for json mode",
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

    if args.output:
        output_path = pathlib.Path(args.output).expanduser()
    else:
        output_path = pathlib.Path("sanitized-backup.zip" if args.mode == "backup" else "sanitized-backup.json")

    extracted = None
    try:
        from .parser import ParseError, load_collections, load_raw_docs, write_raw_docs
    except ModuleNotFoundError:
        print(
            "ERROR: Missing dependency for BSON parsing. Install with: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2

    try:
        extracted = extract_backup(backup_path, backup_password=args.backup_password)

        if args.mode == "json":
            collections = load_collections(extracted.extracted_dir)
            sanitized = {
                "source_backup": pathlib.Path(backup_path).name,
                "collections_count": len(collections),
                "collections": {name: sanitize_obj(items) for name, items in collections.items()},
            }
            output_path.write_text(json.dumps(sanitized, indent=2, default=str), encoding="utf-8")
            print(f"Sanitized snapshot written to: {output_path}")
            return 0

        docs = load_raw_docs(extracted.extracted_dir)
        sanitized_docs = sanitize_obj(docs)
        if not isinstance(sanitized_docs, list):
            print("ERROR: Unexpected sanitizer output shape.", file=sys.stderr)
            return 2
        write_raw_docs(extracted.extracted_dir, sanitized_docs)

        if output_path.suffix.lower() != ".zip":
            output_path = output_path.with_suffix(".zip")
        _zip_dir(extracted.extracted_dir, output_path)
        print(f"Sanitized backup archive written to: {output_path}")
        return 0

    except (BackupExtractionError, ParseError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if extracted and not args.keep_temp:
            extracted.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
