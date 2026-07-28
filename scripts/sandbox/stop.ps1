$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\\..")).Path
$sandboxDir = Join-Path $repoRoot "deploy\\sandbox"
$composeFile = Join-Path $sandboxDir "compose.yaml"
$runtimeDir = Join-Path $sandboxDir "runtime"
$controlTokenFile = Join-Path $runtimeDir "control-token"
$runtimeStateFile = Join-Path $runtimeDir "container-runtime"
$launcherLockDir = Join-Path $runtimeDir "launcher.lock"
$launcherLockPidFile = Join-Path $launcherLockDir "pid"
$generationStatusScript = Join-Path $repoRoot "scripts\sandbox\generation_status.py"
$launcherLockRecoveryMessage = (
    "The sandbox operation lock at $launcherLockDir cannot be verified safely. " +
    "It may belong to another PID namespace or an interrupted launcher with " +
    "active container-engine children. Verify no sandbox launcher, profile " +
    "apply, or container-engine command is running, then remove only that " +
    "lock entry manually and retry."
)
$envFile = Join-Path $sandboxDir ".env"
$runningOnWindows = $env:OS -eq "Windows_NT"
$runningOnLinux = $false
if (Get-Variable IsLinux -ErrorAction SilentlyContinue) {
    $runningOnLinux = [bool]$IsLinux
}

function Test-SandboxRealDirectory {
    param(
        [string]$Path,
        [string]$Description
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return $false
    }
    $isReparsePoint = (
        $item.Attributes -band [System.IO.FileAttributes]::ReparsePoint
    ) -ne 0
    if (-not $item.PSIsContainer -or $isReparsePoint) {
        throw "$Description must be a real directory, not a symlink or reparse point."
    }
    return $true
}

function Test-SandboxRealFile {
    param(
        [string]$Path,
        [string]$Description
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return $false
    }
    $isReparsePoint = (
        $item.Attributes -band [System.IO.FileAttributes]::ReparsePoint
    ) -ne 0
    if ($item.PSIsContainer -or $isReparsePoint) {
        throw "$Description must be a real file, not a symlink or reparse point."
    }
    return $true
}

function Set-SandboxOwnerOnlyDirectoryAcl {
    param([string]$Path)
    if (-not $runningOnWindows) {
        return
    }
    if (-not (Test-SandboxRealDirectory $Path "ACL target")) {
        throw "ACL target directory is missing."
    }
    $ownerSid = (
        [System.Security.Principal.WindowsIdentity]::GetCurrent()
    ).User
    if ($null -eq $ownerSid) {
        throw "Failed to resolve the current Windows security identifier."
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner($ownerSid)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = (
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $ownerSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    $verified = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rules = @(
        $verified.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )
    )
    if (
        -not $verified.AreAccessRulesProtected -or
        $rules.Count -ne 1 -or
        $rules[0].IdentityReference.Value -ne $ownerSid.Value
    ) {
        throw "Failed to verify the owner-only ACL on $Path."
    }
}

if (-not (Test-SandboxRealDirectory $runtimeDir "Sandbox runtime path")) {
    New-Item -ItemType Directory -Path $runtimeDir -ErrorAction Stop | Out-Null
    if (-not (Test-SandboxRealDirectory $runtimeDir "Sandbox runtime path")) {
        throw "Sandbox runtime directory could not be created safely."
    }
}
if ($runningOnWindows) {
    Set-SandboxOwnerOnlyDirectoryAcl $runtimeDir
} else {
    & chmod 700 -- $runtimeDir
}
function Enter-SandboxLauncherLock {
    try {
        [void](Test-SandboxRealDirectory $launcherLockDir "Sandbox operation lock")
    } catch {
        throw $launcherLockRecoveryMessage
    }
    try {
        New-Item -ItemType Directory -Path $launcherLockDir -ErrorAction Stop |
            Out-Null
    } catch {
        try {
            $lockIsReal = Test-SandboxRealDirectory $launcherLockDir "Sandbox operation lock"
            $pidIsReal = Test-SandboxRealFile $launcherLockPidFile "Sandbox operation lock PID"
        } catch {
            throw $launcherLockRecoveryMessage
        }
        if (-not $lockIsReal -or -not $pidIsReal) {
            throw $launcherLockRecoveryMessage
        }
        $ownerText = [System.IO.File]::ReadAllText($launcherLockPidFile)
        $ownerPid = 0
        if (
            -not [int]::TryParse($ownerText, [ref]$ownerPid) -or
            $ownerPid -le 0
        ) {
            throw $launcherLockRecoveryMessage
        }
        if (Get-Process -Id $ownerPid -ErrorAction SilentlyContinue) {
            throw "Another sandbox start, stop, or profile apply is already running (PID $ownerPid)."
        }
        throw $launcherLockRecoveryMessage
    }
    $script:launcherLockHeld = $true
    $pidBytes = [System.Text.Encoding]::ASCII.GetBytes("$PID")
    $pidStream = [System.IO.File]::Open(
        $launcherLockPidFile,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $pidStream.Write($pidBytes, 0, $pidBytes.Length)
    } finally {
        $pidStream.Dispose()
    }
    if ($runningOnWindows) {
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $launcherLockPidFile /inheritance:r /grant:r "${currentIdentity}:(R,W)" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restrict the sandbox launcher lock ACL."
        }
    } else {
        & chmod 600 -- $launcherLockPidFile
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restrict the sandbox launcher lock permissions."
        }
    }
}

function Exit-SandboxLauncherLock {
    if (-not $script:launcherLockHeld) {
        return
    }
    $lockItem = Get-Item -LiteralPath $launcherLockDir -Force -ErrorAction SilentlyContinue
    $lockIsReparsePoint = $null -ne $lockItem -and (
        $lockItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint
    ) -ne 0
    if ($null -ne $lockItem -and $lockItem.PSIsContainer -and -not $lockIsReparsePoint) {
        $pidItem = Get-Item -LiteralPath $launcherLockPidFile -Force -ErrorAction SilentlyContinue
        $pidIsReparsePoint = $null -ne $pidItem -and (
            $pidItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint
        ) -ne 0
        $ownsLock = $null -eq $pidItem -or (
            -not $pidItem.PSIsContainer -and
            -not $pidIsReparsePoint -and
            [System.IO.File]::ReadAllText($launcherLockPidFile) -eq "$PID"
        )
        if ($ownsLock -and $null -ne $pidItem) {
            Remove-Item -LiteralPath $launcherLockPidFile -Force
        }
        if ($ownsLock) {
            Remove-Item -LiteralPath $launcherLockDir -ErrorAction SilentlyContinue
        }
    }
    $script:launcherLockHeld = $false
}

$script:launcherLockHeld = $false
try {
    Enter-SandboxLauncherLock
} catch {
    Exit-SandboxLauncherLock
    throw
}

try {

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
        $line = Get-Content $envFile | Where-Object {
            $_ -match "^$([Regex]::Escape($Name))="
        } | Select-Object -Last 1
        if ($line) {
            return ($line -split "=", 2)[1].Trim()
        }
    }
    return $DefaultValue
}

function Test-SandboxVersionAtLeast {
    param(
        [string]$Value,
        [string]$Minimum
    )
    try {
        return ([version](($Value -split "-", 2)[0])) -ge ([version]$Minimum)
    } catch {
        return $false
    }
}

function Test-SandboxPodman {
    if (-not $runningOnLinux) {
        return $false
    }
    if (-not (Get-Command podman -ErrorAction SilentlyContinue)) {
        return $false
    }
    & podman info *> $null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    & podman compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    $rootless = (& podman info --format "{{.Host.Security.Rootless}}" 2>$null | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or ("$rootless").Trim() -ne "false") {
        return $false
    }
    $version = (& podman version --format "{{.Server.Version}}" 2>$null | Select-Object -Last 1)
    return $LASTEXITCODE -eq 0 -and (Test-SandboxVersionAtLeast $version "5.3")
}

function Test-SandboxDocker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        return $false
    }
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    $version = (& docker version --format "{{.Server.Version}}" 2>$null | Select-Object -Last 1)
    return $LASTEXITCODE -eq 0 -and (Test-SandboxVersionAtLeast $version "28.0")
}

function Get-SandboxPersistedRuntime {
    if (-not (Test-Path -LiteralPath $runtimeStateFile)) {
        return $null
    }
    $item = Get-Item -LiteralPath $runtimeStateFile -Force
    if ($item.PSIsContainer -or $item.LinkType) {
        throw "Sandbox runtime state must be a regular, non-symlink file."
    }
    $bytes = [System.IO.File]::ReadAllBytes($runtimeStateFile)
    $value = [System.Text.Encoding]::ASCII.GetString($bytes)
    if ($bytes.Length -ne 6 -or $value -notin @("docker", "podman")) {
        throw "Sandbox runtime state is malformed; refusing to guess an engine."
    }
    return $value
}

function Resolve-SandboxRecordedRuntime {
    $requested = Get-SandboxEnvValue "SECAI_CONTAINER_RUNTIME" "auto"
    if ($requested -notin @("auto", "podman", "docker")) {
        throw "SECAI_CONTAINER_RUNTIME must be auto, podman, or docker."
    }
    $persisted = Get-SandboxPersistedRuntime
    if ($persisted) {
        if ($requested -ne "auto" -and $requested -ne $persisted) {
            throw "The sandbox is pinned to $persisted; use that runtime to stop it before selecting $requested."
        }
        return $persisted
    }
    switch ($requested) {
        { $_ -in @("podman", "docker") } { return $requested }
        "auto" { return "auto" }
    }
}

$runtimeCmd = Resolve-SandboxRecordedRuntime
$env:COMPOSE_PROJECT_NAME = "secai-sandbox"
$podmanControlNetwork = "secai-sandbox_ingress"
$podmanAnchorScript = Join-Path $repoRoot "scripts\sandbox\podman_anchor.py"
$alpineHelperImage = "docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
}

function Stop-SandboxControlServer {
    if (-not $pythonCmd) {
        return 1
    }
    $controlScript = Join-Path $repoRoot "scripts\sandbox\control_server.py"
    if (-not (Test-Path $controlScript)) {
        return 1
    }
    & $pythonCmd $controlScript `
        --repo-root $repoRoot `
        --runtime-dir $runtimeDir `
        --token-path $controlTokenFile `
        --host auto `
        --runtime $runtimeCmd `
        --podman-network $podmanControlNetwork `
        --port 8498 `
        --stop | Out-Null
    return $LASTEXITCODE
}

$controlCode = Stop-SandboxControlServer
if (
    $controlCode -ne 0 -and
    $runtimeCmd -in @("podman", "auto") -and
    $pythonCmd -and
    (Test-SandboxPodman)
) {
    & $pythonCmd $podmanAnchorScript `
        --runtime-dir $runtimeDir `
        --network $podmanControlNetwork `
        prepare `
        --image $alpineHelperImage | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $controlCode = Stop-SandboxControlServer
    }
}
if ($controlCode -ne 0) {
    throw "The sandbox controller did not confirm a clean stop. Compose teardown was not attempted; wait for any active profile change, then retry."
}

$generationStatusOutput = @(
    & $pythonCmd $generationStatusScript `
        --runtime-dir $runtimeDir `
        invalidate
)
if (
    $LASTEXITCODE -ne 0 -or
    $generationStatusOutput.Count -ne 1 -or
    $generationStatusOutput[0] -notin @("invalidated", "already-invalid")
) {
    throw "The sandbox controller is stopped, but the ready-generation marker could not be invalidated safely; Compose teardown was not attempted."
}

# Compose still expands bind-source variables while parsing `down`. The fixed
# zero ID is deliberately non-authoritative and is never used by the start
# launcher; it only keeps teardown available when the pointer is unavailable.
$env:SECAI_RUNTIME_GENERATION = "0000000000000000000000000000000000000000000000000000000000000000"
$activeGenerationFile = Join-Path $runtimeDir "active-generation"
try {
    if (Test-SandboxRealFile $activeGenerationFile "Active generation pointer") {
        $generationBytes = [System.IO.File]::ReadAllBytes($activeGenerationFile)
        $generationText = [System.Text.Encoding]::ASCII.GetString(
            $generationBytes
        )
        if (
            $generationBytes.Length -eq 64 -and
            $generationText -cmatch "^[0-9a-f]{64}$"
        ) {
            $env:SECAI_RUNTIME_GENERATION = $generationText
        }
    }
} catch {
    $env:SECAI_RUNTIME_GENERATION = "0000000000000000000000000000000000000000000000000000000000000000"
}

if ($runtimeCmd -eq "auto") {
    if (Test-SandboxPodman) {
        $runtimeCmd = "podman"
    } elseif (Test-SandboxDocker) {
        $runtimeCmd = "docker"
    } else {
        throw "The controller is stopped, but no supported legacy runtime is ready for Compose teardown."
    }
} elseif ($runtimeCmd -eq "podman" -and -not (Test-SandboxPodman)) {
    throw "The controller is stopped, but the recorded rootful Podman 5.3+ runtime is not ready for Compose teardown."
} elseif ($runtimeCmd -eq "docker" -and -not (Test-SandboxDocker)) {
    throw "The controller is stopped, but the recorded Docker Server 28+ runtime is not ready for Compose teardown."
}

if ($runtimeCmd -eq "podman") {
    if (-not $pythonCmd) {
        throw "The controller is stopped, but Python is unavailable for safe Podman control-network cleanup."
    }
    & $pythonCmd $podmanAnchorScript `
        --runtime-dir $runtimeDir `
        --network $podmanControlNetwork `
        remove-recorded
    if ($LASTEXITCODE -ne 0) {
        throw "The controller is stopped, but the recorded Podman control-network anchor could not be removed safely."
    }
}

if ($runtimeCmd -eq "docker") {
    & docker compose -f $composeFile --profile search --profile llm --profile diffusion down --remove-orphans
    $code = $LASTEXITCODE
    if ($code -eq 0 -and (Test-Path -LiteralPath $runtimeStateFile)) {
        Remove-Item -LiteralPath $runtimeStateFile -Force
    }
    exit $code
}

if ($runtimeCmd -eq "podman") {
    & podman compose -f $composeFile --profile search --profile llm --profile diffusion down --remove-orphans
    $code = $LASTEXITCODE
    if ($code -eq 0 -and (Test-Path -LiteralPath $runtimeStateFile)) {
        Remove-Item -LiteralPath $runtimeStateFile -Force
    }
    exit $code
}

    throw "Neither docker nor podman was found in PATH."
} finally {
    Exit-SandboxLauncherLock
}
