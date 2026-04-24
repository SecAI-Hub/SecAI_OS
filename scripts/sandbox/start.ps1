param(
    [switch]$WithInference,
    [switch]$WithDiffusion,
    [switch]$WithSearch,
    [switch]$WithAirlock
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\\..")).Path
$sandboxDir = Join-Path $repoRoot "deploy\\sandbox"
$runtimeDir = Join-Path $sandboxDir "runtime"
$envExample = Join-Path $sandboxDir ".env.example"
$envFile = Join-Path $sandboxDir ".env"
$tokenFile = Join-Path $runtimeDir "service-token"
$composeFile = Join-Path $sandboxDir "compose.yaml"
$stateVolume = "secai-sandbox_secai-state"
$runVolume = "secai-sandbox_secai-run"

New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

if (-not (Test-Path $envFile)) {
    Copy-Item $envExample $envFile
    Write-Host "Created $envFile from template."
}

if ((-not (Test-Path $tokenFile)) -or ((Get-Item $tokenFile).Length -eq 0)) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    (($bytes | ForEach-Object { $_.ToString("x2") }) -join "") | Set-Content -Path $tokenFile -NoNewline
    Write-Host "Created sandbox service token at $tokenFile."
}

$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} else {
    throw "python or py is required to render the sandbox runtime configuration."
}

$renderArgs = @(
    (Join-Path $repoRoot "scripts\\sandbox\\render_runtime.py"),
    "--repo-root", $repoRoot,
    "--runtime-dir", $runtimeDir
)
if ($WithSearch -and -not $WithAirlock) {
    $WithAirlock = $true
    Write-Host "Search mode implies the airlock policy in sandbox mode; enabling airlock."
}
if ($WithSearch) {
    $renderArgs += "--enable-search"
}
if ($WithAirlock) {
    $renderArgs += "--enable-airlock"
}
if ($WithDiffusion) {
    $renderArgs += "--enable-diffusion"
}
& $pythonCmd @renderArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if (Get-Command docker -ErrorAction SilentlyContinue) {
    $runtimeCmd = "docker"
    $composeCmd = "docker"
    $composeArgs = @("compose", "-f", $composeFile)
} elseif (Get-Command podman -ErrorAction SilentlyContinue) {
    $runtimeCmd = "podman"
    $composeCmd = "podman"
    $composeArgs = @("compose", "-f", $composeFile)
} else {
    throw "Neither docker nor podman was found in PATH."
}

& $runtimeCmd volume create $stateVolume | Out-Null
& $runtimeCmd volume create $runVolume | Out-Null
& $runtimeCmd run --rm `
    -v "${stateVolume}:/state" `
    -v "${runtimeDir}:/overlay:ro" `
    docker.io/library/alpine:3.20 `
    sh -c "mkdir -p /state/auth /state/import-staging /state/logs /state/quarantine /state/registry /state/state /state/vault/user_docs /state/vault/outputs && if [ -f /overlay/state/profile.json ]; then cp /overlay/state/profile.json /state/state/profile.json; chmod 0644 /state/state/profile.json; fi && chown -R 65534:65534 /state" | Out-Null
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
& $runtimeCmd run --rm `
    -v "${runVolume}:/runstate" `
    docker.io/library/alpine:3.20 `
    sh -c "mkdir -p /runstate && chown -R 65534:65534 /runstate && chmod 0770 /runstate" | Out-Null
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($WithInference) {
    $composeArgs += @("--profile", "llm")
}
if ($WithDiffusion) {
    $composeArgs += @("--profile", "diffusion")
}
if ($WithSearch) {
    $composeArgs += @("--profile", "search")
}

$composeArgs += @("up", "-d", "--build", "--remove-orphans")
if ($runtimeCmd -eq "docker") {
    $composeArgs += "--wait"
}
& $composeCmd @composeArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$uiPort = "8480"
$envLine = Get-Content $envFile | Where-Object { $_ -match "^SECAI_UI_PORT=" } | Select-Object -Last 1
if ($envLine) {
    $uiPort = ($envLine -split "=", 2)[1].Trim()
}
Write-Host "SecAI Sandbox is ready. Open http://127.0.0.1:$uiPort"
