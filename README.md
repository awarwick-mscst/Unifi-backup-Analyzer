# UniFi Helper

Offline UniFi backup auditing toolkit for Debian 12/13 LXC.

## Features
- Analyze UniFi backups (`.unf`, `.zip`, tar/gzip variants where possible)
- Security/performance findings with CIS/NIST-style mappings
- Reports: `text`, `json`, `html`, `csv`
- Web UI with:
  - Analyze flow
  - Sanitize flow (redacted backup zip download)
  - Backup password input for encrypted backups
  - Version badge
- Cloud Key-aware platform detection (`gen1`, `gen2`, `gen2-plus`)
- Strict CI gates (`--strict`, `--strict-score-min`)

## Requirements
- Python 3.10+
- OpenSSL, zip
- Debian 12/13 (target LXC)
- SSH + SCP for deploy/update scripts

## Local Setup
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## CLI Usage
Analyze:
```bash
python -m unifi_audit.cli /path/to/backup.unf --profile cis-nist
```

Encrypted backup:
```bash
python -m unifi_audit.cli /path/to/backup.unf --backup-password 'your-password'
```

Formats:
```bash
python -m unifi_audit.cli /path/to/backup.unf --format json --output report.json
python -m unifi_audit.cli /path/to/backup.unf --format html --output report.html
python -m unifi_audit.cli /path/to/backup.unf --format csv --output remediation.csv
```

Strict gates:
```bash
python -m unifi_audit.cli /path/to/backup.unf --strict
python -m unifi_audit.cli /path/to/backup.unf --strict-score-min 80
python -m unifi_audit.cli /path/to/backup.unf --strict --strict-score-min 80
```

Exit codes:
- `0` success
- `2` runtime/validation error
- `3` strict HIGH-finding gate failed
- `4` strict score gate failed

## Web App
Run:
```bash
source .venv/bin/activate
python -m unifi_audit.webapp --host 0.0.0.0 --port 8080 --max-upload-mb 128
```

Open:
```text
http://<LXC_IP>:8080
```

Notes:
- For encrypted backups, fill `Backup Password`.
- `Analyze Backup` shows report page.
- `Sanitize Backup` downloads a redacted zip backup.

## Sanitizing
Sanitized backup zip:
```bash
python -m unifi_audit.sanitize /path/to/backup.unf --mode backup --output sanitized-backup.zip
```

Sanitized backup zip (encrypted source):
```bash
python -m unifi_audit.sanitize /path/to/backup.unf --backup-password 'your-password' --mode backup --output sanitized-backup.zip
```

Sanitized JSON snapshot:
```bash
python -m unifi_audit.sanitize /path/to/backup.unf --mode json --output sanitized-backup.json
```

## Deploy to LXC
Initial deploy:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\deploy_to_lxc.ps1 `
  -HostName 192.168.1.50 `
  -UserName root `
  -Port 22 `
  -RemoteDir ~/unifi-helper `
  -Bootstrap
```

Update (upload + remote update + service restart):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\update_lxc.ps1 `
  -HostName 192.168.1.50 `
  -UserName root `
  -Port 22 `
  -RemoteDir ~/unifi-helper
```

## systemd Service
Install/enable:
```bash
cd ~/unifi-helper
chmod +x install_systemd_service.sh
./install_systemd_service.sh ~/unifi-helper root 0.0.0.0 8080 128 2G 1500M
```

Manage:
```bash
systemctl status unifi-helper-web.service
systemctl restart unifi-helper-web.service
systemctl stop unifi-helper-web.service
systemctl start unifi-helper-web.service
```

## Lean Resource Guidance
- Typical start: `2 vCPU`, `2 GB RAM`
- Larger sites/backups: `3 vCPU`, `3-4 GB RAM`

## Troubleshooting
- `python: command not found` inside LXC:
  - activate venv: `source ~/unifi-helper/.venv/bin/activate`
- Backup extraction errors:
  - verify file integrity and source path
  - if encrypted, provide `--backup-password` (or web field)
- Find uploaded test `.unf` files on LXC:
  - `find /tmp -maxdepth 1 -type f -name 'unifi_upload_*.unf'`

## Security Note
UniFi backups may contain sensitive network metadata and secrets. Treat raw backups and reports as sensitive data.
