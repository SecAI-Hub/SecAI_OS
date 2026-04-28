rule SecAI_Shell_Dropper_Command
{
    meta:
        description = "Detects shell one-liners commonly used to download and execute payloads"
        severity = "high"
    strings:
        $curl = "curl" ascii nocase
        $wget = "wget" ascii nocase
        $pipe_sh = "| sh" ascii
        $pipe_bash = "| bash" ascii
        $sh_c = "sh -c" ascii
        $bash_c = "bash -c" ascii
    condition:
        filesize < 524288000 and any of ($curl, $wget) and any of ($pipe_sh, $pipe_bash, $sh_c, $bash_c)
}

rule SecAI_Python_Reverse_Shell
{
    meta:
        description = "Detects Python reverse shell building blocks in imported artifacts"
        severity = "high"
    strings:
        $socket = "import socket" ascii
        $subprocess = "subprocess.Popen" ascii
        $dup2 = "os.dup2" ascii
        $binsh = "/bin/sh" ascii
    condition:
        filesize < 524288000 and $socket and $subprocess and $dup2 and $binsh
}

rule SecAI_Embedded_Private_Key
{
    meta:
        description = "Detects embedded private key material inside imported artifacts"
        severity = "high"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $generic = "-----BEGIN PRIVATE KEY-----" ascii
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
    condition:
        filesize < 524288000 and any of them
}

rule SecAI_Encoded_Powershell
{
    meta:
        description = "Detects encoded PowerShell execution payloads"
        severity = "high"
    strings:
        $ps1 = "powershell -enc" ascii nocase
        $ps2 = "powershell.exe -enc" ascii nocase
        $ps3 = "powershell -EncodedCommand" ascii nocase
        $ps4 = "powershell.exe -EncodedCommand" ascii nocase
    condition:
        filesize < 524288000 and any of them
}
