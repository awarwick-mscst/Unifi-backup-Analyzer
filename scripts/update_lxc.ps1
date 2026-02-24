param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,

    [Parameter(Mandatory = $true)]
    [string]$UserName,

    [string]$SourceDir = ".",
    [string]$RemoteDir = "~/unifi-helper",
    [int]$Port = 22,
    [string]$IdentityFile = "",
    [switch]$NoRemoteUpdate,
    [switch]$NoHostKeyCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found in PATH: $Name"
    }
}

Require-Command "scp"
Require-Command "ssh"

$src = (Resolve-Path $SourceDir).Path
if (-not (Test-Path $src)) {
    throw "Source directory not found: $SourceDir"
}

$sshOpts = @("-p", "$Port")
$scpOpts = @("-P", "$Port")
if ($IdentityFile) {
    $sshOpts += @("-i", $IdentityFile)
    $scpOpts += @("-i", $IdentityFile)
}
if ($NoHostKeyCheck) {
    $sshOpts += @("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL")
    $scpOpts += @("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL")
}

$remote = "$UserName@$HostName"

$readmePath = Join-Path $src "README.md"
$requirementsPath = Join-Path $src "requirements.txt"
$packagePath = Join-Path $src "unifi_audit"
$bootstrapPath = Join-Path (Join-Path $src "scripts") "bootstrap_debian.sh"
$updatePath = Join-Path (Join-Path $src "scripts") "update_debian.sh"
$systemdInstallPath = Join-Path (Join-Path $src "scripts") "install_systemd_service.sh"
$systemdUnitPath = Join-Path (Join-Path $src "scripts") "unifi-helper-web.service"

Write-Host "Ensuring remote app directory exists: $RemoteDir"
& ssh @sshOpts $remote "mkdir -p $RemoteDir"

Write-Host "Uploading updated project files..."
& scp @scpOpts -r `
    $readmePath `
    $requirementsPath `
    $packagePath `
    $bootstrapPath `
    $updatePath `
    $systemdInstallPath `
    $systemdUnitPath `
    "${remote}:$RemoteDir/"

if ($LASTEXITCODE -ne 0) {
    throw "scp upload failed with exit code $LASTEXITCODE"
}

Write-Host "Ensuring remote script permissions..."
& ssh @sshOpts $remote "chmod +x $RemoteDir/bootstrap_debian.sh $RemoteDir/update_debian.sh $RemoteDir/install_systemd_service.sh"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to set remote script permissions (chmod +x)."
}

if (-not $NoRemoteUpdate) {
    Write-Host "Running remote update script..."
    & ssh @sshOpts $remote "$RemoteDir/update_debian.sh $RemoteDir"
    if ($LASTEXITCODE -ne 0) {
        throw "Remote update failed with exit code $LASTEXITCODE"
    }

    Write-Host "Restarting unifi-helper-web.service..."
    & ssh @sshOpts $remote @'
if command -v systemctl >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    systemctl daemon-reload
    systemctl restart unifi-helper-web.service
    systemctl is-active --quiet unifi-helper-web.service
  elif command -v sudo >/dev/null 2>&1; then
    sudo systemctl daemon-reload
    sudo systemctl restart unifi-helper-web.service
    sudo systemctl is-active --quiet unifi-helper-web.service
  else
    echo "systemctl available but no privileges to restart service" >&2
    exit 1
  fi
else
  echo "systemctl not available on remote host" >&2
  exit 1
fi
'@
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restart unifi-helper-web.service"
    }
}

Write-Host "Update sync complete."
Write-Host "Remote path: $RemoteDir"
if ($NoRemoteUpdate) {
    Write-Host "Next step:"
    Write-Host "  ssh -p $Port $remote 'chmod +x $RemoteDir/update_debian.sh && $RemoteDir/update_debian.sh $RemoteDir'"
}
