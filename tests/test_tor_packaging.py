"""Keep the Tor account, private state and native socket-group contract aligned."""
import configparser
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSTEM = ROOT / "files/system"


def entries(path):
    return [shlex.split(line, comments=True) for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_tor_account_primary_group_and_state_owner_agree():
    unit = configparser.ConfigParser(interpolation=None, strict=False)
    unit.read(SYSTEM / "usr/lib/systemd/system/secure-ai-tor.service")
    service = unit["Service"]
    assert service["User"] == service["Group"] == "secure-ai-tor"
    assert service.get("DynamicUser", "no") == "no"
    users = entries(SYSTEM / "usr/lib/sysusers.d/secure-ai.conf")
    assert len([line for line in users if line[:2] == ["u", service["User"]]]) == 1
    assert len([line for line in users if line[:2] == ["g", service["Group"]]]) == 1
    state = [line for line in entries(SYSTEM / "usr/lib/tmpfiles.d/secure-ai.conf") if line[1] == "/var/lib/secure-ai/tor"]
    assert len(state) == 1
    assert state[0][:5] == ["d", "/var/lib/secure-ai/tor", "0700", service["User"], service["Group"]]
    # Ordinary d updates the directory itself, never recursively changes or
    # removes existing Tor state; an ownership recovery is an offline action.
    assert service["UMask"] == "0077" and service["RemoveIPC"] == "yes"
    controller = (SYSTEM / "usr/libexec/secure-ai/network-profile.py").read_text()
    assert 'grp.getgrnam("secure-ai-tor").gr_gid' in controller
    rules = (SYSTEM / "etc/nftables/secure-ai.nft").read_text()
    assert "meta skgid $TOR_GID meta l4proto tcp accept" in rules


def test_static_tor_keeps_its_other_restrictions_and_native_boot_dependency():
    text = (SYSTEM / "usr/lib/systemd/system/secure-ai-tor.service").read_text()
    for expected in ["After=secure-ai-network-boot.service", "Requires=secure-ai-network-boot.service", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "NoNewPrivileges=yes", "RestrictSUIDSGID=yes", "PrivateUsers=yes", "PrivateDevices=yes", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "SystemCallFilter=@system-service", "MemoryMax=256M", "TasksMax=64"]:
        assert expected in text
    assert "network-online.target" not in text
    directives = entries(SYSTEM / "etc/secure-ai/tor/torrc")
    for required in [["Sandbox", "1"], ["NoExec", "1"], ["SafeLogging", "1"], ["DataDirectory", "/var/lib/secure-ai/tor"]]:
        assert required in directives
