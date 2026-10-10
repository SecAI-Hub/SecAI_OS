"""Packet qualification; refuses to mutate unless user and net namespaces differ."""

import errno
import importlib.util
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace


def isolated():
    caller = json.loads(os.environ["SECAI_NAMESPACE_PARENT_IDS"])
    for name in ("user", "net"):
        assert re.fullmatch(name + r":\[[0-9]+\]", caller[name])
        assert os.readlink("/proc/self/ns/" + name) != caller[name]
    assert os.geteuid() == 0


def command(*args):
    isolated()
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def peer():
    isolated()
    print("ready", flush=True)
    assert sys.stdin.readline().strip() == "setup"
    command("ip", "link", "set", "peer0", "up")
    command("ip", "addr", "add", "198.18.0.2/24", "dev", "peer0")
    command("ip", "-6", "addr", "add", "2001:db8:88::2/64", "dev", "peer0", "nodad")
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.bind(("peer0", 0))
    markers = []

    def record():
        while True:
            data = capture.recv(8192)
            if b"M03-SYNTHETIC-" in data:
                markers.append(data.split(b"M03-SYNTHETIC-", 1)[1][:24].hex())

    threading.Thread(target=record, daemon=True).start()

    def tcp(server):
        while True:
            client, _ = server.accept()

            def echo(sock):
                with sock:
                    while data := sock.recv(1024):
                        sock.sendall(data)

            threading.Thread(target=echo, args=(client,), daemon=True).start()

    def udp(server):
        while True:
            data, address = server.recvfrom(1024)
            server.sendto(data, address)

    for family, host in [
        (socket.AF_INET, "198.18.0.2"),
        (socket.AF_INET6, "2001:db8:88::2"),
    ]:
        for port in (443, 4444):
            server = socket.socket(family, socket.SOCK_STREAM)
            server.bind((host, port))
            server.listen()
            threading.Thread(target=tcp, args=(server,), daemon=True).start()
        for port in (53, 123):
            server = socket.socket(family, socket.SOCK_DGRAM)
            server.bind((host, port))
            threading.Thread(target=udp, args=(server,), daemon=True).start()
    print("configured", flush=True)
    for line in sys.stdin:
        if line.strip() == "frames":
            print(json.dumps(markers), flush=True)


def smoke(root: Path, nft: str):
    isolated()
    spec = importlib.util.spec_from_file_location(
        "network_policy", root / "files/system/usr/libexec/secure-ai/network-profile.py"
    )
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    # Synthetic root identity tests full_lab socket matching without creating
    # accounts or changing the host's user database. Tor never matches root.
    policy.grp.getgrnam = lambda _: SimpleNamespace(gr_gid=61000)
    policy.pwd.getpwnam = lambda _: SimpleNamespace(pw_uid=0)
    checks = []

    def passed(name):
        checks.append(name)

    with tempfile.TemporaryDirectory(prefix="secai-network-namespace-") as directory:
        temporary = Path(directory)
        source = temporary / "policy.nft"
        source.write_bytes(
            (root / "files/system/etc/nftables/secure-ai.nft").read_bytes()
        )
        source.chmod(0o644)
        resolvers = temporary / "resolv.conf"
        resolvers.write_text("nameserver 198.18.0.2\n")
        controller = policy.Controller(
            nft=nft,
            policy=source,
            state=temporary / "private/policy.json",
            result=temporary / "status.json",
            resolvers=resolvers,
        )

        # This fixture measures packet scopes; the separate resolver/native
        # service fixture qualifies the actual read-only mount receipt.
        def resolver_ready():
            if "127.0.0.53" in resolvers.read_text():
                raise policy.NetworkError("shared resolver binding unavailable")

        controller.verify_resolver = resolver_ready
        subprocess.run(
            [nft, "-f", "-"],
            input="table inet unrelated {\n chain hold {\n type filter hook output priority 100; policy accept;\n }\n}\n",
            text=True,
            check=True,
        )
        assert controller.close()["host_offline"] is True
        passed("cold offline policy and verified wildcard hook")
        command(nft, "list", "table", "inet", "unrelated")
        passed("unrelated table preserved")
        command("ip", "link", "set", "lo", "up")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as local:
            local.bind(("127.0.0.1", 0))
            local.settimeout(1)
            local.sendto(b"local", local.getsockname())
            assert local.recv(32) == b"local"
        passed("loopback remains usable")
        remote = subprocess.Popen(
            ["unshare", "--net", sys.executable, __file__, "--peer"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert remote.stdout.readline().strip() == "ready"
            command(
                "ip", "link", "add", "probe0", "type", "veth", "peer", "name", "peer0"
            )
            command("ip", "link", "set", "peer0", "netns", str(remote.pid))
            command("ip", "link", "set", "probe0", "up")
            command("ip", "addr", "add", "198.18.0.1/24", "dev", "probe0")
            command(
                "ip", "-6", "addr", "add", "2001:db8:88::1/64", "dev", "probe0", "nodad"
            )
            remote.stdin.write("setup\n")
            remote.stdin.flush()
            assert remote.stdout.readline().strip() == "configured"

            def frames():
                time.sleep(0.05)
                remote.stdin.write("frames\n")
                remote.stdin.flush()
                return json.loads(remote.stdout.readline())

            before = frames()
            dhcp_payload = (
                b"\x01\x01\x06\x00"
                + b"\x00" * 232
                + b"\x63\x82\x53\x63\x35\x01\x01\xffM03-SYNTHETIC-DHCP"
            )
            udp_packet = (
                struct.pack("!HHHH", 68, 67, 8 + len(dhcp_payload), 0) + dhcp_payload
            )
            header = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(udp_packet),
                1,
                0,
                64,
                17,
                0,
                b"\x00" * 4,
                b"\xff" * 4,
            )
            checksum = sum(struct.unpack("!10H", header))
            checksum = (checksum & 65535) + (checksum >> 16)
            header = header[:10] + struct.pack("!H", (~checksum) & 65535) + header[12:]
            dhcp_frame = (
                b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01\x08\x00" + header + udp_packet
            )
            # Negative control, confined to this asserted private namespace.
            command(nft, "delete", "table", "netdev", "secure_ai_link")
            command(nft, "add", "table", "arp", "legacy_probe")
            command(
                nft,
                "add",
                "chain",
                "arp",
                "legacy_probe",
                "output",
                "{ type filter hook output priority -300; policy drop; }",
            )
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as raw:
                raw.bind(("probe0", 0))
                raw.send(dhcp_frame)
                raw.send(
                    b"\xff" * 6
                    + b"\x02\x00\x00\x00\x00\x01\x08\x06"
                    + b"M03-SYNTHETIC-ARP"
                    + b"\x00" * 60
                )
            assert len(frames()) >= len(before) + 2
            command(nft, "delete", "table", "arp", "legacy_probe")
            controller.close()
            before = frames()
            passed(
                "negative control: raw DHCP and ARP bypass inet and ARP output hooks alone"
            )
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as raw:
                raw.bind(("probe0", 0))
                for bypass in (0, 1):
                    raw.setsockopt(263, 20, bypass)  # SOL_PACKET / PACKET_QDISC_BYPASS
                    packets = [
                        b"\xff" * 6
                        + b"\x02\x00\x00\x00\x00\x01"
                        + ether
                        + b"M03-SYNTHETIC-RAW"
                        + b"\x00" * 60
                        for ether in (
                            b"\x08\x06",
                            b"\x08\x00",
                            b"\x86\xdd",
                            b"\x88\xb5",
                        )
                    ]
                    for packet in packets + [dhcp_frame]:
                        try:
                            raw.send(packet)
                        except OSError as error:
                            assert error.errno == errno.ENOBUFS
            assert frames() == before
            passed(
                "raw ARP IPv4 IPv6 DHCP and unknown EtherType blocked on new interface including qdisc bypass"
            )
            controller.publish(controller.observe())
            assert controller.result.stat().st_mode & 0o777 == 0o644
            assert controller.state.stat().st_mode & 0o777 == 0o600
            passed("root-only reference and readable status modes")
            for family, host in [
                (socket.AF_INET, "198.18.0.2"),
                (socket.AF_INET6, "2001:db8:88::2"),
            ]:
                with socket.socket(family, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(0.2)
                    for port in (53, 123):
                        try:
                            udp.sendto(b"M03-SYNTHETIC-OFFLINE", (host, port))
                        except PermissionError:
                            pass
                        try:
                            udp.recv(128)
                            raise AssertionError("offline UDP escaped")
                        except TimeoutError:
                            pass
            assert frames() == before
            passed("IPv4 IPv6 DNS and NTP blocked offline")
            assert (
                controller.grant("maintenance", 5)["effective_scope"] == "maintenance"
            )
            controller.publish(controller.observe())
            assert (
                policy.require_maintenance(controller.result)["effective_scope"]
                == "maintenance"
            )
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as raw:
                raw.bind(("probe0", 0))
                raw.send(dhcp_frame)
            assert frames() != before
            passed(
                "valid raw DHCP frame has explicit leased network-configuration exception"
            )
            sockets = []
            for family, host in [
                (socket.AF_INET, "198.18.0.2"),
                (socket.AF_INET6, "2001:db8:88::2"),
            ]:
                client = socket.socket(family, socket.SOCK_STREAM)
                client.settimeout(1)
                client.connect((host, 443))
                client.sendall(b"online")
                assert client.recv(32) == b"online"
                sockets.append(client)
                with socket.socket(family, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(1)
                    for port in (53, 123):
                        udp.sendto(b"online", (host, port))
                        assert udp.recv(32) == b"online"
            passed(
                "maintenance allows declared IPv4 IPv6 HTTPS DNS NTP and neighbor setup"
            )
            time.sleep(5.1)
            for client in sockets:
                client.settimeout(0.25)
                client.sendall(b"after-expiry")
                try:
                    client.recv(32)
                    raise AssertionError("expired established stream escaped")
                except TimeoutError:
                    pass
                client.close()
            assert controller.observe()["host_offline"] is True
            passed(
                "kernel expiry blocks established IPv4 IPv6 flows without controller"
            )
            controller.grant("maintenance", 30)
            client = socket.socket()
            client.settimeout(0.3)
            client.connect(("198.18.0.2", 443))
            client.sendall(b"before-close")
            assert client.recv(32) == b"before-close"
            assert controller.close()["host_offline"] is True
            client.sendall(b"after-close")
            try:
                client.recv(32)
                raise AssertionError("closed established stream escaped")
            except TimeoutError:
                pass
            client.close()
            passed(
                "explicit close blocks an established connection before its lease expires"
            )
            controller.grant("research", 5)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(0.2)
                try:
                    udp.sendto(b"research-root-dns", ("198.18.0.2", 53))
                except PermissionError:
                    pass
                try:
                    udp.recv(32)
                    raise AssertionError("research permitted host DNS")
                except TimeoutError:
                    pass
            passed("research does not grant shared host DNS")
            controller.close()
            controller.grant("full_lab", 5)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(1)
                udp.sendto(b"airlock-direct-dns", ("198.18.0.2", 53))
                assert udp.recv(32) == b"airlock-direct-dns"
            passed("full_lab permits direct resolver under authorized socket UID")
            controller.close()
            resolvers.write_text("nameserver 127.0.0.53\n")
            try:
                controller.grant("full_lab", 5)
                raise AssertionError("shared resolver silently allowed")
            except policy.NetworkError:
                pass
            assert controller.observe()["host_offline"] is True
            passed(
                "shared loopback resolver fails unavailable without host DNS exception"
            )
            command(nft, "add", "rule", "inet", "secure_ai", "output", "accept")
            try:
                controller.observe()
                raise AssertionError("changed rules accepted")
            except policy.NetworkError:
                pass
            controller.close()
            controller.state.unlink()
            try:
                controller.observe()
                raise AssertionError("missing reference recreated")
            except FileNotFoundError:
                pass
            assert not controller.state.exists()
            passed(
                "changed rules or missing reference never report verified or recreate on observation"
            )
            command(nft, "list", "table", "inet", "unrelated")
            passed("unrelated table survives all profile transitions")
        finally:
            remote.terminate()
            remote.wait(timeout=5)
    print(
        json.dumps(
            {"namespace_isolated": True, "checks": checks, "passed": len(checks)}
        )
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["--peer"]:
        peer()
    else:
        smoke(Path(sys.argv[1]), sys.argv[2])
