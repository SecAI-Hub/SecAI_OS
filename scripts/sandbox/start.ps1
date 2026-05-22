param(
    [switch]$WithInference,
    [switch]$WithDiffusion,
    [switch]$WithSearch,
    [switch]$WithAirlock,
    [switch]$WithGpu
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\\..")).Path
$sandboxDir = Join-Path $repoRoot "deploy\\sandbox"
$runtimeDir = Join-Path $sandboxDir "runtime"
$envExample = Join-Path $sandboxDir ".env.example"
$envFile = Join-Path $sandboxDir ".env"
$tokenFile = Join-Path $runtimeDir "service-token"
$controlTokenFile = Join-Path $runtimeDir "control-token"
$composeFile = Join-Path $sandboxDir "compose.yaml"
$nvidiaGpuComposeFile = Join-Path $sandboxDir "compose.gpu.nvidia.yaml"
$rocmGpuComposeFile = Join-Path $sandboxDir "compose.gpu.rocm.yaml"
$stateVolume = "secai-sandbox_secai-state"
$runVolume = "secai-sandbox_secai-run"
$alpineHelperImage = "docker.io/library/alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"

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

if ((-not (Test-Path $controlTokenFile)) -or ((Get-Item $controlTokenFile).Length -eq 0)) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    (($bytes | ForEach-Object { $_.ToString("x2") }) -join "") | Set-Content -Path $controlTokenFile -NoNewline
    Write-Host "Created sandbox control token at $controlTokenFile."
}

$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} else {
    throw "python or py is required to render the sandbox runtime configuration."
}

function Get-SandboxEnvValue {
    param(
        [string]$Name,
        [string]$DefaultValue
    )
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ($value) {
        return $value
    }
    if (Test-Path $envFile) {
        $line = Get-Content $envFile | Where-Object { $_ -match "^$([Regex]::Escape($Name))=" } | Select-Object -Last 1
        if ($line) {
            return ($line -split "=", 2)[1].Trim()
        }
    }
    return $DefaultValue
}

function Resolve-SandboxGpuBackend {
    $configured = Get-SandboxEnvValue "SECAI_DIFFUSION_COMPUTE" ""
    if ($configured -in @("cuda", "rocm")) {
        return $configured
    }
    if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
        return "cuda"
    }
    if (Test-Path "/dev/kfd") {
        return "rocm"
    }
    return "cuda"
}

$controlPort = Get-SandboxEnvValue "SECAI_CONTROL_PORT" "8498"

function Test-SandboxControlServer {
    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$controlPort/health" -TimeoutSec 1
        return $resp.status -eq "ok"
    } catch {
        return $false
    }
}

if (-not (Test-SandboxControlServer)) {
    $controlOut = Join-Path $runtimeDir "control-server.out.log"
    $controlErr = Join-Path $runtimeDir "control-server.err.log"
    $controlScript = Join-Path $repoRoot "scripts\sandbox\control_server.py"
    $controlArgs = @(
        "`"$controlScript`"",
        "--repo-root", "`"$repoRoot`"",
        "--runtime-dir", "`"$runtimeDir`"",
        "--token-path", "`"$controlTokenFile`"",
        "--host", "127.0.0.1",
        "--port", $controlPort
    )
    Start-Process -WindowStyle Hidden -FilePath $pythonCmd -ArgumentList $controlArgs -RedirectStandardOutput $controlOut -RedirectStandardError $controlErr
    Start-Sleep -Milliseconds 500
    if (Test-SandboxControlServer) {
        Write-Host "Sandbox control server is listening on http://127.0.0.1:$controlPort."
    } else {
        Write-Warning "Sandbox control server did not answer yet; UI automation may be unavailable until it starts."
    }
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
if ($WithGpu -and -not $WithDiffusion) {
    $WithDiffusion = $true
    Write-Host "GPU acceleration implies the diffusion profile; enabling diffusion."
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
} elseif (Get-Command podman -ErrorAction SilentlyContinue) {
    $runtimeCmd = "podman"
    $composeCmd = "podman"
} else {
    throw "Neither docker nor podman was found in PATH."
}

$composeFileArgs = @("-f", $composeFile)
if ($WithGpu) {
    $gpuBackend = Resolve-SandboxGpuBackend
    if ($gpuBackend -eq "rocm") {
        $gpuComposeFile = $rocmGpuComposeFile
    } else {
        $gpuBackend = "cuda"
        $gpuComposeFile = $nvidiaGpuComposeFile
    }
    $env:SECAI_DIFFUSION_COMPUTE = $gpuBackend
    if (-not $env:SECAI_DIFFUSION_DEVICE_PREFERENCE) {
        $env:SECAI_DIFFUSION_DEVICE_PREFERENCE = "auto"
    }
    if (-not $env:SECAI_DIFFUSION_CPU_OFFLOAD) {
        $env:SECAI_DIFFUSION_CPU_OFFLOAD = "0"
    }
    $composeFileArgs += @("-f", $gpuComposeFile)
    Write-Host "GPU acceleration requested for diffusion ($gpuBackend)."
}
$composeArgs = @("compose") + $composeFileArgs

& $runtimeCmd volume create $stateVolume | Out-Null
& $runtimeCmd volume create $runVolume | Out-Null
& $runtimeCmd run --rm `
    -v "${stateVolume}:/state" `
    -v "${runtimeDir}:/overlay:ro" `
    $alpineHelperImage `
    sh -c "mkdir -p /state/auth /state/import-staging /state/logs /state/quarantine /state/registry /state/state /state/vault/user_docs /state/vault/outputs && if [ -f /overlay/state/profile.json ]; then cp /overlay/state/profile.json /state/state/profile.json; chmod 0644 /state/state/profile.json; fi && chown -R 65534:65534 /state" | Out-Null
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
& $runtimeCmd run --rm `
    -v "${runVolume}:/runstate" `
    $alpineHelperImage `
    sh -c "mkdir -p /runstate && chown -R 65534:65534 /runstate && chmod 0770 /runstate" | Out-Null
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$allProfileComposeArgs = @(
    "compose"
) + $composeFileArgs + @(
    "--profile", "search",
    "--profile", "llm",
    "--profile", "diffusion"
)
$disabledServices = @()
if (-not $WithSearch) {
    $disabledServices += @("tor", "searxng")
}
if (-not $WithInference) {
    $disabledServices += "inference"
}
if (-not $WithDiffusion) {
    $disabledServices += "diffusion"
}
if ($disabledServices.Count -gt 0) {
    $rmArgs = $allProfileComposeArgs + @("rm", "-sf") + $disabledServices
    & $composeCmd @rmArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
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
    $composeArgs += @("--wait-timeout", "900")
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
