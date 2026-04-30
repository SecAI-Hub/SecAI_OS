# Download a SecAI OS release source bundle and launch the Docker sandbox.

[CmdletBinding()]
param(
    [string]$Repo = "SecAI-Hub/SecAI_OS",
    [string]$Tag = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\SecAI_OS\sandbox",
    [ValidateSet("offline-private", "offline", "research", "web", "full-lab", "lab")]
    [string]$Profile = "offline-private",
    [switch]$WithSearch,
    [switch]$WithDiffusion,
    [switch]$WithInference,
    [switch]$WithGpu,
    [switch]$Refresh,
    [switch]$InstallDeps,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Info($Message) {
    Write-Host "[+] $Message"
}

function Warn($Message) {
    Write-Warning $Message
}

function Fail($Message) {
    throw "[x] $Message"
}

if ($Repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    Fail "--repo must look like OWNER/REPO"
}

if ($Tag -ne "latest" -and $Tag -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$') {
    Fail "--tag contains unsupported characters"
}

switch ($Profile) {
    { $_ -in @("offline-private", "offline") } {
        $Profile = "offline-private"
        break
    }
    { $_ -in @("research", "web") } {
        $Profile = "research"
        $WithSearch = $true
        break
    }
    { $_ -in @("full-lab", "lab") } {
        $Profile = "full-lab"
        $WithSearch = $true
        $WithDiffusion = $true
        break
    }
}

$StartFlags = @()
if ($WithSearch) { $StartFlags += "--with-search" }
if ($WithDiffusion) { $StartFlags += "--with-diffusion" }
if ($WithInference) { $StartFlags += "--with-inference" }
if ($WithGpu) { $StartFlags += "--with-gpu" }

function Resolve-LatestTag {
    $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "secai-os-release-helper" }
    return $latest.tag_name
}

if ($Tag -eq "latest") {
    $Tag = Resolve-LatestTag
}

if ($DryRun) {
    Info "Dry run: Docker sandbox launch plan"
    Write-Host "  repo:        $Repo"
    Write-Host "  tag:         $Tag"
    Write-Host "  install dir: $InstallDir"
    Write-Host "  profile:     $Profile"
    Write-Host "  flags:       $($StartFlags -join ' ')"
    exit 0
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    if ($InstallDeps) {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Warn "Installing Docker Desktop with winget. A reboot or manual Docker Desktop start may still be required."
            winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
        } else {
            Fail "Docker is not installed and winget is unavailable. Install Docker Desktop, then rerun this script."
        }
    } else {
        Fail "Docker is not installed. Install Docker Desktop or rerun with -InstallDeps."
    }
}

try {
    docker compose version | Out-Null
} catch {
    Fail "Docker Compose v2 is required. Update Docker Desktop, then rerun this script."
}

try {
    docker info | Out-Null
} catch {
    $service = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Running") {
        Warn "Docker service is not running; attempting to start it."
        Start-Service -Name "com.docker.service"
        Start-Sleep -Seconds 5
    }
}

try {
    docker info | Out-Null
} catch {
    Fail "Docker daemon is not reachable. Start Docker Desktop, then rerun this script."
}

if ((Test-Path $InstallDir) -and $Refresh) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

if (-not (Test-Path $InstallDir)) {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("secai-os-" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    try {
        $zipPath = Join-Path $tempRoot "secai-os-$Tag.zip"
        $url = "https://github.com/$Repo/archive/refs/tags/$Tag.zip"
        Info "Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $zipPath -Headers @{ "User-Agent" = "secai-os-release-helper" }
        Expand-Archive -Path $zipPath -DestinationPath $tempRoot
        $sourceDir = Get-ChildItem -Path $tempRoot -Directory | Where-Object { $_.Name -like "SecAI_OS-*" -or $_.Name -like "SecAI_OS*" } | Select-Object -First 1
        if (-not $sourceDir) {
            Fail "Downloaded source archive did not contain the expected directory"
        }
        New-Item -ItemType Directory -Path (Split-Path -Parent $InstallDir) -Force | Out-Null
        Move-Item -LiteralPath $sourceDir.FullName -Destination $InstallDir
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Info "Using existing install directory $InstallDir"
}

$launcher = Join-Path $InstallDir "secai-sandbox.cmd"
if (-not (Test-Path $launcher)) {
    Fail "Sandbox launcher not found at $launcher"
}

Info "Starting Docker sandbox ($Profile)"
Push-Location $InstallDir
try {
    & $launcher start @StartFlags
} finally {
    Pop-Location
}

Info "SecAI OS Docker sandbox is starting at http://127.0.0.1:8480"
