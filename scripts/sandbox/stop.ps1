$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\\..")).Path
$sandboxDir = Join-Path $repoRoot "deploy\\sandbox"
$composeFile = Join-Path $sandboxDir "compose.yaml"

if (Get-Command docker -ErrorAction SilentlyContinue) {
    & docker compose -f $composeFile --profile search --profile llm --profile diffusion down --remove-orphans
    exit $LASTEXITCODE
}

if (Get-Command podman -ErrorAction SilentlyContinue) {
    & podman compose -f $composeFile --profile search --profile llm --profile diffusion down --remove-orphans
    exit $LASTEXITCODE
}

throw "Neither docker nor podman was found in PATH."
