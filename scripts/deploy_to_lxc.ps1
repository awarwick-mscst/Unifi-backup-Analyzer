param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,

    [Parameter(Mandatory = $true)]
    [string]$UserName,

    [string]$SourceDir = ".",
    [string]$RemoteDir = "~/unifi-helper",
    [int]$Port = 22,
    [string]$IdentityFile = "",
    [switch]$Bootstrap,
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

Write-Host "Creating remote app directory: $RemoteDir"
& ssh @sshOpts $remote "mkdir -p $RemoteDir"

Write-Host "Uploading project files with scp..."
$readmePath = Join-Path $src "README.md"
$requirementsPath = Join-Path $src "requirements.txt"
$packagePath = Join-Path $src "unifi_audit"
$bootstrapPath = Join-Path (Join-Path $src "scripts") "bootstrap_debian.sh"
$updatePath = Join-Path (Join-Path $src "scripts") "update_debian.sh"
$systemdInstallPath = Join-Path (Join-Path $src "scripts") "install_systemd_service.sh"
$systemdUnitPath = Join-Path (Join-Path $src "scripts") "unifi-helper-web.service"

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

if ($Bootstrap) {
    Write-Host "Running remote bootstrap..."
    & ssh @sshOpts $remote "chmod +x $RemoteDir/bootstrap_debian.sh && $RemoteDir/bootstrap_debian.sh $RemoteDir"
    if ($LASTEXITCODE -ne 0) {
        throw "Remote bootstrap failed with exit code $LASTEXITCODE"
    }
}

Write-Host "Deploy complete."
Write-Host "Remote path: $RemoteDir"
if (-not $Bootstrap) {
    Write-Host "Next step:"
    Write-Host "  ssh -p $Port $remote 'chmod +x $RemoteDir/bootstrap_debian.sh && $RemoteDir/bootstrap_debian.sh $RemoteDir'"
}
