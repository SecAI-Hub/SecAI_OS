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
$composeFile = Join-Path $sandboxDir "compose.yaml"
$nvidiaGpuComposeFile = Join-Path $sandboxDir "compose.gpu.nvidia.yaml"
$rocmGpuComposeFile = Join-Path $sandboxDir "compose.gpu.rocm.yaml"
$legacyStateVolume = "secai-sandbox_secai-state"
$registryVolume = "secai-sandbox_secai-registry"
$promotionVolume = "secai-sandbox_secai-promotion-staging"
$quarantineVolume = "secai-sandbox_secai-quarantine"
$scannerJobsVolume = "secai-sandbox_secai-quarantine-scanner-jobs"
$vaultVolume = "secai-sandbox_secai-vault"
$logsVolume = "secai-sandbox_secai-logs"
$authVolume = "secai-sandbox_secai-auth"
$importVolume = "secai-sandbox_secai-import-staging"
$uiRootVolume = "secai-sandbox_secai-ui-root"
$agentStateVolume = "secai-sandbox_secai-agent-state"
$runVolume = "secai-sandbox_secai-run"
$runningOnWindows = $env:OS -eq "Windows_NT"
$runningOnLinux = $false
if (Get-Variable IsLinux -ErrorAction SilentlyContinue) {
    $runningOnLinux = [bool]$IsLinux
}
$alpineHelperImage = "docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"

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

function Set-SandboxOwnerOnlyAcl {
    param(
        [string]$Path,
        [switch]$Directory
    )
    if (-not $runningOnWindows) {
        return
    }
    if ($Directory) {
        if (-not (Test-SandboxRealDirectory $Path "ACL target")) {
            throw "ACL target directory is missing."
        }
    } elseif (-not (Test-SandboxRealFile $Path "ACL target")) {
        throw "ACL target file is missing."
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $ownerSid = $identity.User
    if ($null -eq $ownerSid) {
        throw "Failed to resolve the current Windows security identifier."
    }
    if ($Directory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
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
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $ownerSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    }
    $acl.SetOwner($ownerSid)
    $acl.SetAccessRuleProtection($true, $false)
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
        $rules[0].IdentityReference.Value -ne $ownerSid.Value -or
        $rules[0].AccessControlType -ne
            [System.Security.AccessControl.AccessControlType]::Allow
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
    Set-SandboxOwnerOnlyAcl $runtimeDir -Directory
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

if (-not (Test-SandboxRealFile $envExample "Sandbox environment template")) {
    throw "Sandbox environment template is missing."
}
if (-not (Test-SandboxRealFile $envFile "Sandbox .env")) {
    $temporaryEnvFile = Join-Path $sandboxDir (
        ".$([System.IO.Path]::GetFileName($envFile)).$PID." +
        "$([Guid]::NewGuid().ToString('N')).tmp"
    )
    $sourceStream = $null
    $targetStream = $null
    try {
        $sourceStream = [System.IO.File]::Open(
            $envExample,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $targetStream = [System.IO.File]::Open(
            $temporaryEnvFile,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $sourceStream.CopyTo($targetStream)
        $targetStream.Flush($true)
    } finally {
        if ($null -ne $targetStream) {
            $targetStream.Dispose()
        }
        if ($null -ne $sourceStream) {
            $sourceStream.Dispose()
        }
    }
    try {
        if ($runningOnWindows) {
            Set-SandboxOwnerOnlyAcl $temporaryEnvFile
        }
        try {
            [System.IO.File]::Move($temporaryEnvFile, $envFile)
            Write-Host "Created $envFile from template."
        } catch {
            if (-not (Test-SandboxRealFile $envFile "Sandbox .env")) {
                throw
            }
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryEnvFile) {
            if (Test-SandboxRealFile $temporaryEnvFile "Temporary sandbox .env") {
                Remove-Item -LiteralPath $temporaryEnvFile -Force
            }
        }
    }
}
if (-not (Test-SandboxRealFile $envFile "Sandbox .env")) {
    throw "Sandbox .env could not be created safely."
}
$envStream = [System.IO.File]::Open(
    $envFile,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::ReadWrite,
    [System.IO.FileShare]::Read
)
try {
    $envStream.Flush($true)
} finally {
    $envStream.Dispose()
}
if ($runningOnWindows) {
    Set-SandboxOwnerOnlyAcl $envFile
} else {
    & chmod 600 -- $envFile
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restrict sandbox .env permissions."
    }
}

$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} else {
    throw "python or py is required to render the sandbox runtime configuration."
}

$tokenProvisionArgs = @(
    (Join-Path $repoRoot "scripts\\sandbox\\provision_control_token.py"),
    "--runtime-dir", $runtimeDir,
    "--token-path", $controlTokenFile
)
$tokenProvisionStatus = (& $pythonCmd @tokenProvisionArgs | Select-Object -Last 1)
if (
    $LASTEXITCODE -ne 0 -or
    $tokenProvisionStatus -notin @("created", "existing")
) {
    throw "Sandbox control token is malformed. Do not delete runtime metadata while a controller may be active; stop the recorded controller, verify port 8498 is closed, then remove only the token to regenerate it."
}
if ($tokenProvisionStatus -eq "created") {
    Write-Host "Created sandbox control token at $controlTokenFile."
}
if ($runningOnWindows) {
    Set-SandboxOwnerOnlyAcl $controlTokenFile
}
# Revalidate the exact inode and payload after applying the platform ACL.
$postAclTokenStatus = (& $pythonCmd @tokenProvisionArgs | Select-Object -Last 1)
if ($LASTEXITCODE -ne 0 -or $postAclTokenStatus -ne "existing") {
    throw "Failed to validate the restricted sandbox control token."
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

function Test-SandboxVersionAtLeast {
    param(
        [string]$Value,
        [string]$Minimum
    )
    try {
        $normalized = ($Value -split "-", 2)[0]
        return ([version]$normalized) -ge ([version]$Minimum)
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
    if ($runningOnWindows) {
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $runtimeStateFile /inheritance:r /grant:r "${currentIdentity}:(R,W)" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restrict the sandbox runtime state ACL."
        }
    } else {
        & chmod 600 -- $runtimeStateFile
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restrict the sandbox runtime state permissions."
        }
    }
    return $value
}

function Set-SandboxPersistedRuntime {
    param([string]$Value)
    $temporaryPath = "$runtimeStateFile.tmp.$PID.$([Guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllBytes(
            $temporaryPath,
            [System.Text.Encoding]::ASCII.GetBytes($Value)
        )
        if ($runningOnWindows) {
            $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            & icacls $temporaryPath /inheritance:r /grant:r "${currentIdentity}:(R,W)" | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to restrict the temporary sandbox runtime state ACL."
            }
        } else {
            & chmod 600 -- $temporaryPath
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to restrict the temporary sandbox runtime state permissions."
            }
        }
        try {
            Move-Item -LiteralPath $temporaryPath -Destination $runtimeStateFile -ErrorAction Stop
        } catch {
            $racedValue = Get-SandboxPersistedRuntime
            if ($racedValue -ne $Value) {
                throw "A concurrent launcher pinned the sandbox to $racedValue; refusing to continue with $Value."
            }
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Select-SandboxContainerRuntime {
    $requested = Get-SandboxEnvValue "SECAI_CONTAINER_RUNTIME" "auto"
    if ($requested -notin @("auto", "podman", "docker")) {
        throw "SECAI_CONTAINER_RUNTIME must be auto, podman, or docker."
    }
    $persisted = Get-SandboxPersistedRuntime
    if ($persisted) {
        if ($requested -ne "auto" -and $requested -ne $persisted) {
            throw "The sandbox is pinned to $persisted; stop it before selecting $requested."
        }
        if ($persisted -eq "podman" -and -not (Test-SandboxPodman)) {
            throw "The recorded rootful Podman 5.3+ runtime is not ready; refusing to switch engines."
        }
        if ($persisted -eq "docker" -and -not (Test-SandboxDocker)) {
            throw "The recorded Docker Server 28+ runtime is not ready; refusing to switch engines."
        }
        return $persisted
    }
    switch ($requested) {
        "podman" {
            if (-not (Test-SandboxPodman)) {
                throw "Rootful Podman 5.3+ must be installed and running for SECAI_CONTAINER_RUNTIME=podman; rootless host-loopback routing is unsupported."
            }
            $selected = "podman"
        }
        "docker" {
            if (-not (Test-SandboxDocker)) {
                throw "Docker Server 28+ must be installed and running for SECAI_CONTAINER_RUNTIME=docker."
            }
            $selected = "docker"
        }
        "auto" {
            if (Test-SandboxPodman) {
                $selected = "podman"
            } elseif (Test-SandboxDocker) {
                $selected = "docker"
            } else {
                throw "No supported runtime is ready; start rootful Podman 5.3+ or Docker Server 28+."
            }
        }
    }
    Set-SandboxPersistedRuntime $selected
    return $selected
}

$runtimeCmd = Select-SandboxContainerRuntime
$composeCmd = $runtimeCmd
$env:COMPOSE_PROJECT_NAME = "secai-sandbox"
$podmanControlNetwork = "secai-sandbox_ingress"
$podmanAnchorScript = Join-Path $repoRoot "scripts\sandbox\podman_anchor.py"
$podmanAnchorId = ""
$podmanAnchorLaunchId = ""
$podmanAnchorOwned = $false
$controlReady = $false
$runtimeRenderer = Join-Path $repoRoot "scripts\\sandbox\\render_runtime.py"

$earlyControllerMetadata = (
    (Test-Path -LiteralPath (Join-Path $runtimeDir "control-server-host")) -or
    (Test-Path -LiteralPath (Join-Path $runtimeDir "control-server.pid"))
)
if ($earlyControllerMetadata) {
    $earlyControlScript = Join-Path $repoRoot "scripts\sandbox\control_server.py"
    & $pythonCmd $earlyControlScript `
        --repo-root $repoRoot `
        --runtime-dir $runtimeDir `
        --token-path $controlTokenFile `
        --host auto `
        --runtime $runtimeCmd `
        --podman-network $podmanControlNetwork `
        --port 8498 `
        --probe 2>$null | Out-Null
    $earlyControlProbeStatus = $LASTEXITCODE
    if ($earlyControlProbeStatus -ne 0) {
        & $pythonCmd $earlyControlScript `
            --repo-root $repoRoot `
            --runtime-dir $runtimeDir `
            --token-path $controlTokenFile `
            --host auto `
            --runtime $runtimeCmd `
            --podman-network $podmanControlNetwork `
            --port 8498 `
            --stop 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "The existing sandbox controller could not be retired safely. Readiness and Compose services were left unchanged; stop the controller with its matching launcher and retry."
        }
    }
}

$priorGenerationOutput = @(
    & $pythonCmd $runtimeRenderer `
        --runtime-dir $runtimeDir `
        --read-active 2>$null
)
if (
    $LASTEXITCODE -eq 0 -and
    $priorGenerationOutput.Count -eq 1 -and
    $priorGenerationOutput[0] -cmatch "^[0-9a-f]{64}$"
) {
    $env:SECAI_RUNTIME_GENERATION = $priorGenerationOutput[0]
} else {
    # Parse-only fallback for Compose stop. The renderer overwrites it before
    # any `up`, so this value can never select a runnable generation.
    $env:SECAI_RUNTIME_GENERATION = "0000000000000000000000000000000000000000000000000000000000000000"
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
    throw "The prior sandbox ready-generation marker could not be invalidated safely; existing services were not stopped."
}
$generationStatusDir = Join-Path $runtimeDir "generation-status"
if ($runningOnWindows) {
    Set-SandboxOwnerOnlyAcl $generationStatusDir -Directory
}
Write-Host "Quiescing existing sandbox services before runtime generation publication."
& $composeCmd compose -f $composeFile `
    --profile search `
    --profile llm `
    --profile diffusion `
    stop
if ($LASTEXITCODE -ne 0) {
    throw "Existing sandbox services could not be quiesced; runtime generation publication was not attempted."
}
$runningProjectContainers = @(
    & $runtimeCmd ps -q `
        --filter "label=com.docker.compose.project=secai-sandbox"
)
if ($LASTEXITCODE -ne 0) {
    throw "Container runtime state could not be verified after sandbox quiesce."
}
if (@($runningProjectContainers | Where-Object { "$_".Trim() }).Count -ne 0) {
    throw "Sandbox project containers remain running after Compose stop; runtime generation publication was not attempted."
}

if ($runtimeCmd -eq "podman") {
    $anchorOutput = @(
        & $pythonCmd $podmanAnchorScript `
            --runtime-dir $runtimeDir `
            --network $podmanControlNetwork `
            prepare `
            --image $alpineHelperImage
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Could not prepare the project-scoped Podman control network."
    }
    $anchorFields = ("$anchorOutput").Trim() -split "\s+"
    if (
        $anchorFields.Count -ge 4 -and
        $anchorFields[1] -cmatch "^[0-9a-f]{64}$" -and
        $anchorFields[2] -cmatch "^[0-9a-f]{64}$" -and
        $anchorFields[3] -eq "1"
    ) {
        $podmanAnchorId = $anchorFields[1]
        $podmanAnchorLaunchId = $anchorFields[2]
        $podmanAnchorOwned = $true
    }
    if (
        $anchorFields.Count -ne 4 -or
        $anchorFields[1] -cnotmatch "^[0-9a-f]{64}$" -or
        $anchorFields[2] -cnotmatch "^[0-9a-f]{64}$" -or
        $anchorFields[3] -notin @("0", "1")
    ) {
        throw "Podman control-network anchor returned malformed ownership data."
    }
    $podmanAnchorId = $anchorFields[1]
    $podmanAnchorLaunchId = $anchorFields[2]
    $podmanAnchorOwned = $anchorFields[3] -eq "1"
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

$configuredControlPort = Get-SandboxEnvValue "SECAI_CONTROL_PORT" ""
if ($configuredControlPort -and $configuredControlPort -ne "8498") {
    throw "SECAI_CONTROL_PORT is no longer configurable; the fixed relay requires port 8498."
}
$controlPort = 8498
$controlScript = Join-Path $repoRoot "scripts\sandbox\control_server.py"

function Get-SandboxControlProbeStatus {
    & $pythonCmd $controlScript `
        --repo-root $repoRoot `
        --runtime-dir $runtimeDir `
        --token-path $controlTokenFile `
        --host auto `
        --runtime $runtimeCmd `
        --podman-network $podmanControlNetwork `
        --port $controlPort `
        --probe 2>$null | Out-Null
    return $LASTEXITCODE
}

$controllerStarted = $false
$controlProcess = $null
$startupComplete = $false
    $controlProbeStatus = Get-SandboxControlProbeStatus
    $controlReady = $controlProbeStatus -eq 0
    if ($controlProbeStatus -ne 0) {
        if ($controlProbeStatus -eq 2) {
            throw "An authenticated sandbox controller with an older protocol is running. Wait for any active profile change, stop it with its matching launcher, then retry."
        }
        $controlOut = Join-Path $runtimeDir "control-server.out.log"
        $controlErr = Join-Path $runtimeDir "control-server.err.log"
        $controlArgs = @(
            "`"$controlScript`"",
            "--repo-root", "`"$repoRoot`"",
            "--runtime-dir", "`"$runtimeDir`"",
            "--token-path", "`"$controlTokenFile`"",
            "--host", "auto",
            "--runtime", $runtimeCmd,
            "--podman-network", $podmanControlNetwork,
            "--port", $controlPort
        )
        $controlProcess = Start-Process -PassThru -WindowStyle Hidden -FilePath $pythonCmd -ArgumentList $controlArgs -RedirectStandardOutput $controlOut -RedirectStandardError $controlErr
        $controllerStarted = $true
        $controlReady = $false
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            Start-Sleep -Milliseconds 100
            if ((Get-SandboxControlProbeStatus) -eq 0) {
                $controlReady = $true
                break
            }
        }
        if (-not $controlReady) {
            throw "Sandbox control server failed to start; see $controlErr."
        }
        Write-Host "Sandbox control server is listening on a host-local endpoint at port $controlPort."
    }

    $recordedControlHostPath = Join-Path $runtimeDir "control-server-host"
    if (-not (Test-Path -LiteralPath $recordedControlHostPath)) {
        throw "The recorded sandbox controller address is missing."
    }
    $recordedControlHost = (
        [System.IO.File]::ReadAllText($recordedControlHostPath)
    ).Trim()
    $controlAddress = $null
    if (
        -not [System.Net.IPAddress]::TryParse(
            $recordedControlHost,
            [ref]$controlAddress
        ) -or
        $controlAddress.AddressFamily -ne
            [System.Net.Sockets.AddressFamily]::InterNetwork
    ) {
        throw "The recorded sandbox controller address is invalid."
    }
    $addressBytes = $controlAddress.GetAddressBytes()
    $isLoopback = $addressBytes[0] -eq 127
    $isPrivate = (
        $addressBytes[0] -eq 10 -or
        (
            $addressBytes[0] -eq 172 -and
            $addressBytes[1] -ge 16 -and
            $addressBytes[1] -le 31
        ) -or
        (
            $addressBytes[0] -eq 192 -and
            $addressBytes[1] -eq 168
        )
    )
    if (-not $isLoopback -and -not $isPrivate) {
        throw "The recorded sandbox controller address is not loopback or RFC 1918."
    }
    $env:SECAI_CONTROL_HOST_GATEWAY = if ($isLoopback) {
        "host-gateway"
    } else {
        $controlAddress.ToString()
    }

if ($runningOnWindows) {
    $credentialsDir = Join-Path $runtimeDir "credentials"
    if (-not (Test-SandboxRealDirectory $credentialsDir "Credential directory")) {
        New-Item -ItemType Directory -Path $credentialsDir -ErrorAction Stop |
            Out-Null
    }
    if (-not (Test-SandboxRealDirectory $credentialsDir "Credential directory")) {
        throw "Credential directory could not be created safely."
    }
    # Apply an owner-only inheritable DACL before the renderer creates any
    # temporary or final credential inode within this directory.
    Set-SandboxOwnerOnlyAcl $credentialsDir -Directory
}

$renderArgs = @(
    $runtimeRenderer,
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
$renderOutput = @(& $pythonCmd @renderArgs)
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
if (
    $renderOutput.Count -ne 1 -or
    $renderOutput[0] -cnotmatch "^[0-9a-f]{64}$"
) {
    throw "Sandbox runtime renderer returned an invalid generation ID."
}
$env:SECAI_RUNTIME_GENERATION = $renderOutput[0]
if ($runningOnWindows) {
    if (-not (Test-SandboxRealDirectory $credentialsDir "Credential directory")) {
        throw "Credential directory is missing after runtime rendering."
    }
    Set-SandboxOwnerOnlyAcl $credentialsDir -Directory
    $credentialNames = @(
        "airlock", "agent", "agent-audit", "agent-signing", "diffusion",
        "policy-engine", "registry", "quarantine-audit", "search-mediator",
        "search-mediator-audit", "searxng", "tool-firewall", "ui-audit",
        "ui-flask", "ui-setup"
    )
    foreach ($credentialName in $credentialNames) {
        $credentialPath = Join-Path $credentialsDir "$credentialName.token"
        if (-not (Test-SandboxRealFile $credentialPath "Service credential")) {
            throw "Service credential is missing: $credentialName"
        }
        $credential = [System.IO.File]::ReadAllText($credentialPath)
        if ($credential -cnotmatch "^[0-9a-f]{64}$") {
            throw "Service credential is malformed: $credentialName"
        }
        Set-SandboxOwnerOnlyAcl $credentialPath
    }
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

@(
    $registryVolume,
    $promotionVolume,
    $quarantineVolume,
    $scannerJobsVolume,
    $vaultVolume,
    $logsVolume,
    $authVolume,
    $importVolume,
    $uiRootVolume,
    $agentStateVolume,
    $runVolume
) | ForEach-Object {
    & $runtimeCmd volume create $_ | Out-Null
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
& $runtimeCmd run --rm `
    --network none `
    --read-only `
    --cap-drop ALL `
    --cap-add CHOWN `
    --cap-add DAC_OVERRIDE `
    --cap-add FOWNER `
    --security-opt no-new-privileges `
    --pids-limit 64 `
    --memory 64m `
    --cpus 0.50 `
    -v "${registryVolume}:/volumes/registry" `
    -v "${promotionVolume}:/volumes/promotion" `
    -v "${quarantineVolume}:/volumes/quarantine" `
    -v "${scannerJobsVolume}:/volumes/scanner-jobs" `
    -v "${vaultVolume}:/volumes/vault" `
    -v "${logsVolume}:/volumes/logs" `
    -v "${authVolume}:/volumes/auth" `
    -v "${importVolume}:/volumes/import-staging" `
    -v "${uiRootVolume}:/volumes/ui-root" `
    -v "${agentStateVolume}:/volumes/agent-state" `
    $alpineHelperImage `
    sh -c "mkdir -p /volumes/registry /volumes/promotion /volumes/quarantine/incoming /volumes/quarantine/processing /volumes/scanner-jobs /volumes/vault/user_docs /volumes/vault/outputs /volumes/logs /volumes/auth /volumes/import-staging/.tmp /volumes/ui-root/state /volumes/ui-root/data /volumes/agent-state && chown -R 65534:65534 /volumes/registry /volumes/promotion /volumes/quarantine /volumes/scanner-jobs /volumes/vault /volumes/logs /volumes/auth /volumes/import-staging /volumes/ui-root /volumes/agent-state && chown -R 65534:65532 /volumes/quarantine/processing && chmod 2750 /volumes/quarantine/processing && chown -R 0:65533 /volumes/scanner-jobs && find /volumes/scanner-jobs -mindepth 1 -maxdepth 1 -type f -exec chmod 0640 {} + && chmod 0700 /volumes/auth /volumes/import-staging /volumes/promotion /volumes/agent-state && chmod 2770 /volumes/scanner-jobs" | Out-Null
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
& $runtimeCmd volume inspect $legacyStateVolume *> $null
if ($LASTEXITCODE -eq 0) {
    & $runtimeCmd run --rm `
        --network none `
        --read-only `
        --cap-drop ALL `
        --cap-add CHOWN `
        --cap-add DAC_OVERRIDE `
        --cap-add FOWNER `
        --security-opt no-new-privileges `
        --pids-limit 64 `
        --memory 64m `
        --cpus 0.50 `
        -v "${legacyStateVolume}:/legacy:ro" `
        -v "${registryVolume}:/volumes/registry" `
        -v "${quarantineVolume}:/volumes/quarantine" `
        -v "${vaultVolume}:/volumes/vault" `
        -v "${logsVolume}:/volumes/logs" `
        -v "${authVolume}:/volumes/auth" `
        -v "${importVolume}:/volumes/import-staging" `
        -v "${uiRootVolume}:/volumes/ui-root" `
        $alpineHelperImage `
        sh -c "for item in registry quarantine vault logs auth import-staging; do if [ -d `"/legacy/`$item`" ] && [ -z `"`$(ls -A `"/volumes/`$item`" 2>/dev/null)`" ]; then cp -a `"/legacy/`$item/.`" `"/volumes/`$item/`"; fi; done; if [ -d /legacy/state ] && [ -z `"`$(ls -A /volumes/ui-root/state 2>/dev/null)`" ]; then cp -a /legacy/state/. /volumes/ui-root/state/; fi; chown -R 65534:65534 /volumes/registry /volumes/quarantine /volumes/vault /volumes/logs /volumes/auth /volumes/import-staging /volumes/ui-root; chown -R 65534:65532 /volumes/quarantine/processing; chmod 2750 /volumes/quarantine/processing" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    Write-Host "Migrated legacy sandbox state into least-privilege service volumes where empty."
}
& $runtimeCmd run --rm `
    --network none `
    --read-only `
    --cap-drop ALL `
    --cap-add CHOWN `
    --cap-add DAC_OVERRIDE `
    --cap-add FOWNER `
    --security-opt no-new-privileges `
    --pids-limit 64 `
    --memory 64m `
    --cpus 0.50 `
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

$composeArgs += @("up", "-d", "--build", "--remove-orphans", "--force-recreate")
if ($runtimeCmd -eq "docker") {
    $composeArgs += "--wait"
    $composeArgs += @("--wait-timeout", "900")
}
& $composeCmd @composeArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($runtimeCmd -eq "podman") {
    $healthComposeArgs = @("compose") + $composeFileArgs
    if ($WithInference) {
        $healthComposeArgs += @("--profile", "llm")
    }
    if ($WithDiffusion) {
        $healthComposeArgs += @("--profile", "diffusion")
    }
    if ($WithSearch) {
        $healthComposeArgs += @("--profile", "search")
    }
    $services = @(& $composeCmd @healthComposeArgs config --services)
    if ($LASTEXITCODE -ne 0 -or $services.Count -eq 0) {
        throw "Podman Compose did not report any enabled sandbox services."
    }
    $stackHealth = "waiting"
    for ($attempt = 0; $attempt -lt 1800; $attempt++) {
        $stackHealth = "healthy"
        foreach ($serviceName in $services) {
            $serviceContainers = @(
                & $runtimeCmd ps -aq --no-trunc `
                    --filter "label=com.docker.compose.project=secai-sandbox" `
                    --filter "label=com.docker.compose.service=$serviceName" `
                    2>$null
            )
            $enumerateCode = $LASTEXITCODE
            $serviceContainers = @(
                $serviceContainers |
                    ForEach-Object { "$_".Trim() } |
                    Where-Object { $_ }
            )
            if ($enumerateCode -ne 0) {
                throw "Podman could not enumerate sandbox service $serviceName."
            }
            if ($serviceContainers.Count -eq 0) {
                $stackHealth = "waiting"
                continue
            }
            if ($serviceContainers.Count -ne 1) {
                throw "Podman reported multiple containers for sandbox service $serviceName."
            }
            $serviceContainer = $serviceContainers[0]
            $serviceState = (
                & $runtimeCmd inspect `
                    --format "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" `
                    $serviceContainer 2>$null |
                    Select-Object -Last 1
            )
            switch ($serviceState) {
                { $_ -in @("running|healthy", "running|none") } {}
                { $_ -in @("running|starting", "running|") } {
                    $stackHealth = "waiting"
                }
                "running|unhealthy" {
                    throw "Podman reported sandbox service $serviceName as unhealthy."
                }
                "" {
                    $stackHealth = "waiting"
                }
                default {
                    throw "Podman reported sandbox service $serviceName in state $serviceState."
                }
            }
        }
        if ($stackHealth -eq "healthy") {
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if ($stackHealth -ne "healthy") {
        throw "Timed out waiting for Podman sandbox health after 900 seconds."
    }
    & $pythonCmd $podmanAnchorScript `
        --runtime-dir $runtimeDir `
        --network $podmanControlNetwork `
        remove-recorded
    if ($LASTEXITCODE -ne 0) {
        throw "The Podman control-network anchor could not be removed safely."
    }
    $podmanAnchorOwned = $false
}

$generationStatusOutput = @(
    & $pythonCmd $generationStatusScript `
        --runtime-dir $runtimeDir `
        publish `
        --generation $env:SECAI_RUNTIME_GENERATION
)
if (
    $LASTEXITCODE -ne 0 -or
    $generationStatusOutput.Count -ne 1 -or
    $generationStatusOutput[0] -notin @("published", "already-ready")
) {
    throw "Sandbox services passed health checks, but readiness could not be published safely."
}
if ($runningOnWindows) {
    $readyGenerationFile = Join-Path $generationStatusDir "ready-generation"
    $readySessionFile = Join-Path $generationStatusDir "ready-session"
    Set-SandboxOwnerOnlyAcl $generationStatusDir -Directory
    Set-SandboxOwnerOnlyAcl $readyGenerationFile
    Set-SandboxOwnerOnlyAcl $readySessionFile
    $verifiedReadyState = @(
        & $pythonCmd $generationStatusScript `
            --runtime-dir $runtimeDir `
            read
    )
    $verifiedReadyFields = (
        "$verifiedReadyState"
    ).Trim() -split "\s+"
    if (
        $LASTEXITCODE -ne 0 -or
        $verifiedReadyState.Count -ne 1 -or
        $verifiedReadyFields.Count -ne 2 -or
        $verifiedReadyFields[0] -cne $env:SECAI_RUNTIME_GENERATION -or
        $verifiedReadyFields[1] -cnotmatch "^[0-9a-f]{64}$"
    ) {
        throw "The restricted sandbox ready-generation/session state could not be verified."
    }
}

$uiPort = "8480"
$envLine = Get-Content $envFile | Where-Object { $_ -match "^SECAI_UI_PORT=" } | Select-Object -Last 1
if ($envLine) {
    $uiPort = ($envLine -split "=", 2)[1].Trim()
}
Write-Host "First-boot setup credential: $(Join-Path $runtimeDir 'credentials\\ui-setup.token')"
Write-Host "SecAI Sandbox is ready. Open http://127.0.0.1:$uiPort"
    $startupComplete = $true
} finally {
    try {
        $anchorCleanupSafe = $true
        if ($controllerStarted -and -not $startupComplete) {
            & $pythonCmd $controlScript `
                --repo-root $repoRoot `
                --runtime-dir $runtimeDir `
                --token-path $controlTokenFile `
                --host auto `
                --runtime $runtimeCmd `
                --podman-network $podmanControlNetwork `
                --port $controlPort `
                --stop *> $null
            if ($LASTEXITCODE -ne 0) {
                $anchorCleanupSafe = $false
                throw "Startup failed and the controller could not confirm safe process-tree cleanup; it was left running fail-closed."
            }
            if ($controlProcess) {
                Wait-Process -Id $controlProcess.Id -ErrorAction SilentlyContinue
            }
        } elseif ($controlReady -and -not $startupComplete) {
            $anchorCleanupSafe = $false
        }
        if (
            $runtimeCmd -eq "podman" -and
            $podmanAnchorOwned -and
            $anchorCleanupSafe
        ) {
            & $pythonCmd $podmanAnchorScript `
                --runtime-dir $runtimeDir `
                --network $podmanControlNetwork `
                remove-owned `
                --container-id $podmanAnchorId `
                --launch-id $podmanAnchorLaunchId *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Startup failed and the owned Podman control-network anchor could not be removed safely."
            }
        }
    } finally {
        Exit-SandboxLauncherLock
    }
}
