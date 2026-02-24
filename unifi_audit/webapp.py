from __future__ import annotations

import argparse
import io
import secrets
import tempfile
import time
import zipfile
from dataclasses import asdict
from pathlib import Path
from threading import Lock
from typing import Any

from .backup import BackupExtractionError, extract_backup
from .checks import run_checks
from .reporting import to_csv, to_html, to_json, to_text
from .sanitize import sanitize_obj
from . import __version__

ALLOWED_EXTENSIONS = {".unf", ".zip"}
REPORT_TTL_SECONDS = 300
REPORT_MAX_ITEMS = 20
DEFAULT_MAX_UPLOAD_MB = 128

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


class ReportStore:
    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self._lock = Lock()

    def put(self, report: Any) -> str:
        token = secrets.token_urlsafe(20)
        with self._lock:
            self._gc_locked()
            self._data[token] = {"created": time.time(), "report": report}
        return token

    def get(self, token: str) -> Any | None:
        with self._lock:
            self._gc_locked()
            obj = self._data.get(token)
            return None if not obj else obj["report"]

    def _gc_locked(self) -> None:
        now = time.time()
        expired = [k for k, v in self._data.items() if (now - v["created"]) > REPORT_TTL_SECONDS]
        for key in expired:
            del self._data[key]
        if len(self._data) > REPORT_MAX_ITEMS:
            ordered = sorted(self._data.items(), key=lambda kv: kv[1]["created"])
            for key, _ in ordered[: len(self._data) - REPORT_MAX_ITEMS]:
                del self._data[key]


STORE = ReportStore()


def create_app(max_upload_mb: int = DEFAULT_MAX_UPLOAD_MB):
    from flask import Flask, abort, redirect, render_template, request, send_file, url_for
    from werkzeug.utils import secure_filename

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = max_upload_mb * 1024 * 1024

    def _zip_dir_to_bytes(source_dir: Path) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in source_dir.rglob("*"):
                if path.is_file():
                    zf.write(path, arcname=path.relative_to(source_dir))
        buf.seek(0)
        return buf.read()

    @app.get("/")
    def home() -> str:
        return render_template("index.html", app_version=__version__)

    @app.post("/analyze")
    def analyze() -> str:
        try:
            from .parser import ParseError, load_collections
        except ModuleNotFoundError:
            return render_template(
                "index.html",
                error="Missing BSON dependency. Install with: pip install -r requirements.txt",
                app_version=__version__,
            ), 500

        upload = request.files.get("backup")
        if not upload or not upload.filename:
            return render_template(
                "index.html",
                error="Please select a UniFi backup file (.unf or .zip).",
                app_version=__version__,
            ), 400

        filename = secure_filename(upload.filename)
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return render_template(
                "index.html",
                error="Unsupported file type. Use .unf or .zip",
                app_version=__version__,
            ), 400

        action = request.form.get("action", "analyze").strip().lower()
        if action not in {"analyze", "sanitize"}:
            action = "analyze"
        backup_password = (request.form.get("backup_password") or "").strip() or None

        profile = request.form.get("profile", "cis-nist")
        if profile not in {"baseline", "cis-nist"}:
            profile = "cis-nist"

        strict = request.form.get("strict") == "on"
        strict_score_raw = (request.form.get("strict_score_min") or "").strip()
        strict_score_min: int | None = None
        if strict_score_raw:
            try:
                strict_score_min = int(strict_score_raw)
                if strict_score_min < 0 or strict_score_min > 100:
                    raise ValueError
            except ValueError:
                return render_template(
                    "index.html",
                    error="Strict score minimum must be an integer from 0-100.",
                    app_version=__version__,
                ), 400

        tmp_file = tempfile.NamedTemporaryFile(prefix="unifi_upload_", suffix=ext, delete=False)
        tmp_path = Path(tmp_file.name)
        try:
            upload.save(tmp_path)
            extracted = extract_backup(str(tmp_path), backup_password=backup_password)
            try:
                if action == "sanitize":
                    try:
                        from .parser import ParseError, load_raw_docs, write_raw_docs
                    except ModuleNotFoundError:
                        return render_template(
                            "index.html",
                            error="Missing BSON dependency. Install with: pip install -r requirements.txt",
                            app_version=__version__,
                        ), 500
                    docs = load_raw_docs(extracted.extracted_dir)
                    sanitized_docs = sanitize_obj(docs)
                    if not isinstance(sanitized_docs, list):
                        return render_template(
                            "index.html",
                            error="Sanitization failed due to invalid document shape.",
                            app_version=__version__,
                        ), 500
                    write_raw_docs(extracted.extracted_dir, sanitized_docs)
                    payload = _zip_dir_to_bytes(extracted.extracted_dir)
                    out_name = f"{Path(filename).stem}-sanitized.zip"
                    return send_file(
                        io.BytesIO(payload),
                        mimetype="application/zip",
                        as_attachment=True,
                        download_name=out_name,
                    )

                collections = load_collections(extracted.extracted_dir, allowlist=AUDIT_COLLECTION_ALLOWLIST)
                report = run_checks(backup_path=filename, collections=collections, profile=profile)
            finally:
                extracted.cleanup()
        except (BackupExtractionError, ParseError) as exc:
            return render_template(
                "index.html",
                error=f"Failed to process backup: {exc}",
                app_version=__version__,
            ), 400
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

        has_high = any(f.severity.upper() == "HIGH" for f in report.findings)
        strict_failed = strict and has_high
        score_failed = strict_score_min is not None and report.score < strict_score_min
        gate_status = "pass"
        if strict_failed or score_failed:
            gate_status = "fail"

        token = STORE.put(report)
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in report.findings:
            sev = finding.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return render_template(
            "result.html",
            report=report,
            report_dict=asdict(report),
            token=token,
            severity_counts=severity_counts,
            strict=strict,
            strict_score_min=strict_score_min,
            strict_failed=strict_failed,
            score_failed=score_failed,
            gate_status=gate_status,
            app_version=__version__,
        )

    @app.get("/download/<token>/<fmt>")
    def download(token: str, fmt: str):
        report = STORE.get(token)
        if report is None:
            abort(404)

        if fmt == "json":
            payload = to_json(report).encode("utf-8")
            return send_file(
                io.BytesIO(payload),
                mimetype="application/json",
                as_attachment=True,
                download_name="unifi-audit-report.json",
            )
        if fmt == "csv":
            payload = to_csv(report).encode("utf-8")
            return send_file(
                io.BytesIO(payload),
                mimetype="text/csv",
                as_attachment=True,
                download_name="unifi-audit-remediation.csv",
            )
        if fmt == "html":
            payload = to_html(report).encode("utf-8")
            return send_file(
                io.BytesIO(payload),
                mimetype="text/html",
                as_attachment=True,
                download_name="unifi-audit-report.html",
            )
        if fmt == "text":
            payload = to_text(report).encode("utf-8")
            return send_file(
                io.BytesIO(payload),
                mimetype="text/plain",
                as_attachment=True,
                download_name="unifi-audit-report.txt",
            )
        abort(404)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/new")
    def new_scan():
        return redirect(url_for("home"))

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="unifi-audit-web", description="Run UniFi Helper web UI.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument(
        "--max-upload-mb",
        type=int,
        default=DEFAULT_MAX_UPLOAD_MB,
        help=f"Maximum backup upload size in MB (default: {DEFAULT_MAX_UPLOAD_MB})",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        import flask  # noqa: F401
    except ModuleNotFoundError:
        raise SystemExit("ERROR: Missing dependency 'Flask'. Install with: pip install -r requirements.txt")
    app = create_app(max_upload_mb=args.max_upload_mb)
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
