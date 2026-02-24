from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import zipfile
import os
import tarfile
import gzip
from dataclasses import dataclass


# UniFi Network backup AES-128-CBC key/IV (hex-encoded).
# Source parity: zhangyoufu/unifi-backup-decrypt
UNIFI_BACKUP_KEY = os.environ.get(
    "UNIFI_BACKUP_KEY_HEX", "626379616e676b6d6c756f686d617273"
)
UNIFI_BACKUP_IV = os.environ.get(
    "UNIFI_BACKUP_IV_HEX", "75626e74656e74657270726973656170"
)
HEAVY_FIX_AUTOMATIC_MAX_MB = int(os.environ.get("UNIFI_AUDIT_HEAVY_FIX_AUTOMATIC_MAX_MB", "16"))


def _env_bool(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return None


@dataclass
class ExtractedBackup:
    workdir: pathlib.Path
    extracted_dir: pathlib.Path

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


class BackupExtractionError(RuntimeError):
    pass


def _run(cmd: list[str], timeout: int | None = None, input_text: str | None = None) -> None:
    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "(no stderr)"
        raise BackupExtractionError(f"Command failed: {' '.join(cmd)}\n{stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise BackupExtractionError(f"Command timed out: {' '.join(cmd)}") from exc


def _decrypt_unf(source: pathlib.Path, output: pathlib.Path) -> None:
    _run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-128-cbc",
            "-K",
            UNIFI_BACKUP_KEY,
            "-iv",
            UNIFI_BACKUP_IV,
            "-nopad",
            "-in",
            str(source),
            "-out",
            str(output),
        ]
    )


def _decrypt_unf_padded(source: pathlib.Path, output: pathlib.Path) -> None:
    # Some UniFi backups behave better with PKCS#7 unpadding enabled.
    _run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-128-cbc",
            "-K",
            UNIFI_BACKUP_KEY,
            "-iv",
            UNIFI_BACKUP_IV,
            "-in",
            str(source),
            "-out",
            str(output),
        ]
    )


def _decrypt_with_password(
    source: pathlib.Path, output: pathlib.Path, password: str, cipher: str, pbkdf2: bool
) -> None:
    cmd = [
        "openssl",
        "enc",
        "-d",
        f"-{cipher}",
        "-in",
        str(source),
        "-out",
        str(output),
        "-pass",
        f"pass:{password}",
    ]
    if pbkdf2:
        cmd.extend(["-pbkdf2", "-md", "sha256"])
    _run(cmd)


def _decrypt_with_password_candidates(
    source: pathlib.Path, workdir: pathlib.Path, password: str
) -> list[pathlib.Path]:
    candidates: list[pathlib.Path] = []
    profiles = [
        ("aes-256-cbc", True),
        ("aes-256-cbc", False),
        ("aes-128-cbc", True),
        ("aes-128-cbc", False),
    ]
    for idx, (cipher, use_pbkdf2) in enumerate(profiles):
        out = workdir / f"decrypted_pass_{idx}.bin"
        try:
            _decrypt_with_password(source, out, password=password, cipher=cipher, pbkdf2=use_pbkdf2)
            candidates.append(out)
        except BackupExtractionError:
            continue
    return candidates


def _has_archive_signature(path: pathlib.Path) -> bool:
    try:
        data = path.read_bytes()[:8192]
    except OSError:
        return False
    return (b"PK\x03\x04" in data) or (b"\x1f\x8b" in data) or (b"ustar" in data)


def _try_trim_zip(broken_zip: pathlib.Path, fixed_zip: pathlib.Path) -> bool:
    data = broken_zip.read_bytes()
    sig = b"PK\x05\x06"
    # Search backward for End Of Central Directory marker.
    idx = data.rfind(sig)
    if idx < 0 or idx + 22 > len(data):
        return False
    comment_len = int.from_bytes(data[idx + 20 : idx + 22], "little")
    end = idx + 22 + comment_len
    if end > len(data):
        return False
    fixed_zip.write_bytes(data[:end])
    return zipfile.is_zipfile(fixed_zip)


def _try_fix_zip(broken_zip: pathlib.Path, fixed_zip: pathlib.Path) -> bool:
    try:
        # zip -FF can ask interactive repair questions; provide automatic "yes" responses.
        _run(
            ["zip", "-FF", str(broken_zip), "--out", str(fixed_zip)],
            timeout=12,
            input_text=("y\n" * 64),
        )
        return zipfile.is_zipfile(fixed_zip)
    except BackupExtractionError:
        return False


def _looks_like_gzip(path: pathlib.Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def _extract_archive_candidate(
    candidate: pathlib.Path, extracted_dir: pathlib.Path, workdir: pathlib.Path
) -> bool:
    # Zip
    if zipfile.is_zipfile(candidate):
        with zipfile.ZipFile(candidate, "r") as zf:
            zf.extractall(extracted_dir)
        return True

    # Tar (including .tar.gz that tarfile can auto-detect)
    if tarfile.is_tarfile(candidate):
        with tarfile.open(candidate, "r:*") as tf:
            tf.extractall(extracted_dir)
        return True

    # Gzip blob that may wrap tar/zip/raw db
    if _looks_like_gzip(candidate):
        decompressed = workdir / f"{candidate.stem}_decompressed.bin"
        with gzip.open(candidate, "rb") as gz:
            decompressed.write_bytes(gz.read())

        if tarfile.is_tarfile(decompressed):
            with tarfile.open(decompressed, "r:*") as tf:
                tf.extractall(extracted_dir)
            return True
        if zipfile.is_zipfile(decompressed):
            with zipfile.ZipFile(decompressed, "r") as zf:
                zf.extractall(extracted_dir)
            return True

        # Fallback: assume raw db stream payload.
        raw_db = extracted_dir / "db"
        raw_db.write_bytes(decompressed.read_bytes())
        return True

    return False


def extract_backup(backup_path: str, backup_password: str | None = None) -> ExtractedBackup:
    source = pathlib.Path(backup_path).expanduser().resolve()
    if not source.exists():
        raise BackupExtractionError(f"Backup file does not exist: {source}")

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="unifi_audit_"))
    extracted_dir = workdir / "extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    # First, try extracting the source as-is (Cloud Key backups may be tar/gzip based).
    if _extract_archive_candidate(source, extracted_dir, workdir):
        return ExtractedBackup(workdir=workdir, extracted_dir=extracted_dir)

    # Then try known .unf decrypt flows.
    decrypt_candidates: list[pathlib.Path] = []
    if backup_password:
        decrypt_candidates.extend(_decrypt_with_password_candidates(source, workdir, backup_password))

    decrypted_nopad = workdir / "decrypted_nopad.bin"
    try:
        _decrypt_unf(source, decrypted_nopad)
        decrypt_candidates.append(decrypted_nopad)
    except BackupExtractionError:
        pass

    decrypted_padded = workdir / "decrypted_padded.bin"
    try:
        _decrypt_unf_padded(source, decrypted_padded)
        decrypt_candidates.append(decrypted_padded)
    except BackupExtractionError:
        pass

    for decrypted in decrypt_candidates:
        if _extract_archive_candidate(decrypted, extracted_dir, workdir):
            return ExtractedBackup(workdir=workdir, extracted_dir=extracted_dir)

        # Repair only if decrypted has plausible archive signatures.
        if not _has_archive_signature(decrypted):
            continue

        repaired_trim = workdir / f"{decrypted.stem}_trimmed.zip"
        if _try_trim_zip(decrypted, repaired_trim):
            if _extract_archive_candidate(repaired_trim, extracted_dir, workdir):
                return ExtractedBackup(workdir=workdir, extracted_dir=extracted_dir)

        force_heavy = _env_bool("UNIFI_AUDIT_ALLOW_HEAVY_ZIP_FIX")
        if force_heavy is None:
            allow_heavy = decrypted.stat().st_size <= (HEAVY_FIX_AUTOMATIC_MAX_MB * 1024 * 1024)
        else:
            allow_heavy = force_heavy
        if allow_heavy:
            repaired = workdir / f"{decrypted.stem}_fixed.zip"
            if _try_fix_zip(decrypted, repaired) and _extract_archive_candidate(repaired, extracted_dir, workdir):
                return ExtractedBackup(workdir=workdir, extracted_dir=extracted_dir)

    raise BackupExtractionError(
        "Backup extraction failed: unsupported, password-protected, or corrupted backup format after direct extract and decryption attempts."
    )
