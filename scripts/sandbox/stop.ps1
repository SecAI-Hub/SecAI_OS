$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\\..")).Path
$sandboxDir = Join-Path $repoRoot "deploy\\sandbox"
$composeFile = Join-Path $sandboxDir "compose.yaml"
$runtimeDir = Join-Path $sandboxDir "runtime"
$envFile = Join-Path $sandboxDir ".env"
$controlTokenFile = Join-Path $runtimeDir "control-token"

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

function Stop-SandboxControlServer {
    $pythonCmd = $null
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $pythonCmd = "python"
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $pythonCmd = "py"
    }
    if (-not $pythonCmd) {
        return
    }
    $controlScript = Join-Path $repoRoot "scripts\sandbox\control_server.py"
    if (-not (Test-Path $controlScript)) {
        return
    }
    $controlPort = Get-SandboxEnvValue "SECAI_CONTROL_PORT" "8498"
    & $pythonCmd $controlScript `
        --repo-root $repoRoot `
        --runtime-dir $runtimeDir `
        --token-path $controlTokenFile `
        --host 127.0.0.1 `
        --port $controlPort `
        --stop | Out-Null
}

if (Get-Command docker -ErrorAction SilentlyContinue) {
    & docker compose -f $composeFile --profile search --profile llm --profile diffusion down --remove-orphans
    $code = $LASTEXITCODE
    Stop-SandboxControlServer
    exit $code
}

if (Get-Command podman -ErrorAction SilentlyContinue) {
    & podman compose -f $composeFile --profile search --profile llm --profile diffusion down --remove-orphans
    $code = $LASTEXITCODE
    Stop-SandboxControlServer
    exit $code
}

throw "Neither docker nor podman was found in PATH."
