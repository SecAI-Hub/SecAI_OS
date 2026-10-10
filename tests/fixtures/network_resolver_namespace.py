"""Actual Airlock DNS/TLS plus resolver inode binding in private namespaces."""

import hashlib
import http.server
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace


def isolated():
    caller = json.loads(os.environ["SECAI_NAMESPACE_PARENT_IDS"])
    for name in ("user", "net", "mnt"):
        assert re.fullmatch(name + r":\[[0-9]+\]", caller[name])
        assert os.readlink("/proc/self/ns/" + name) != caller[name]
    assert os.geteuid() == 0


def run(*args):
    isolated()
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def load(root):
    spec = importlib.util.spec_from_file_location(
        "network_profile",
        root / "files/system/usr/libexec/secure-ai/network-profile.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def peer(cert, key):
    isolated()
    print("ready", flush=True)
    assert sys.stdin.readline().strip() == "setup"
    run("ip", "link", "set", "peer0", "up")
    for address in ("198.18.0.2/24", "11.0.0.2/24"):
        run("ip", "addr", "add", address, "dev", "peer0")
    hits = {"dns": 0, "tls": 0}
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(("198.18.0.2", 53))

    def answer():
        while True:
            data, address = dns.recvfrom(4096)
            end = 12
            while data[end]:
                end += data[end] + 1
            end += 1
            kind = struct.unpack("!H", data[end : end + 2])[0]
            question = data[12 : end + 4]
            hits["dns"] += 1
            reply = (
                data[:2]
                + struct.pack("!HHHHH", 0x8180, 1, int(kind == 1), 0, 0)
                + question
            )
            if kind == 1:
                reply += (
                    b"\xc0\x0c"
                    + struct.pack("!HHIH", 1, 1, 0, 4)
                    + socket.inet_aton("11.0.0.2")
                )
            dns.sendto(reply, address)

    threading.Thread(target=answer, daemon=True).start()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits["tls"] += 1
            content = b"synthetic DNS and TLS response"
            self.send_response(200)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("11.0.0.2", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("configured", flush=True)
    for line in sys.stdin:
        if line.strip() == "hits":
            print(json.dumps(hits), flush=True)


def launch_service(root, prepared, binary):
    isolated()
    module = load(Path(root))
    run("mount", "--make-rprivate", "/")
    run("mount", "--bind", prepared, "/etc/resolv.conf")
    run("mount", "-o", "remount,bind,ro", prepared, "/etc/resolv.conf")
    boot = os.environ["SECAI_NETWORK_BOOT_ID_PATH"]
    Path(boot).touch()
    run("mount", "--bind", "/proc/sys/kernel/random/boot_id", boot)
    run(
        "mount",
        "-o",
        "remount,bind,ro,nosuid,nodev,noexec",
        "/proc/sys/kernel/random/boot_id",
        boot,
    )
    os.setgroups([])
    os.setgid(1)
    os.setuid(1)
    module.attest_resolver()
    os.execv(binary, [binary])


def smoke(root, nft, binary):
    isolated()
    checks = []
    with tempfile.TemporaryDirectory(prefix="secai-resolver-namespace-") as name:
        temp = Path(name)
        temp.chmod(0o755)
        copied_binary = temp / "airlock"
        shutil.copyfile(binary, copied_binary)
        copied_binary.chmod(0o755)
        run("mount", "--make-rprivate", "/")
        (temp / "run").mkdir()
        run("mount", "--bind", str(temp / "run"), "/run")
        # Recreate this host's stub target only inside the private /run mount.
        stub = Path("/etc/resolv.conf").resolve()
        assert str(stub).startswith("/run/")
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text("nameserver 127.0.0.53\n")
        stub.chmod(0o644)
        uplink = Path("/run/NetworkManager/no-stub-resolv.conf")
        uplink.parent.mkdir()
        uplink.write_text("nameserver 198.18.0.2\n")
        uplink.chmod(0o644)
        receipt_dir = Path("/run/secure-ai-airlock-resolver")
        receipt_dir.mkdir(mode=0o755)
        os.chown(receipt_dir, 1, 1)
        module = load(root)
        module.grp.getgrnam = lambda _: SimpleNamespace(gr_gid=61000)
        module.pwd.getpwnam = lambda _: SimpleNamespace(pw_uid=1)
        policy = temp / "policy.nft"
        policy.write_bytes(
            (root / "files/system/etc/nftables/secure-ai.nft").read_bytes()
        )
        policy.chmod(0o644)
        controller = module.Controller(
            nft=nft,
            policy=policy,
            state=Path("/run/secure-ai-network/policy.json"),
            result=Path("/run/secure-ai/network-status.json"),
        )
        controller.close()
        controller.prepare_resolver()
        before_global = Path("/etc/resolv.conf").read_bytes()
        cert, key = temp / "cert.pem", temp / "key.pem"
        run(
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=network-fixture.example",
            "-addext",
            "subjectAltName=DNS:network-fixture.example",
        )
        cert.chmod(0o644)
        remote = subprocess.Popen(
            [
                "unshare",
                "--net",
                sys.executable,
                __file__,
                "--peer",
                str(cert),
                str(key),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        process = None
        try:
            assert remote.stdout.readline().strip() == "ready"
            run("ip", "link", "set", "lo", "up")
            run("ip", "link", "add", "probe0", "type", "veth", "peer", "name", "peer0")
            run("ip", "link", "set", "peer0", "netns", str(remote.pid))
            run("ip", "link", "set", "probe0", "up")
            for address in ("198.18.0.1/24", "11.0.0.1/24"):
                run("ip", "addr", "add", address, "dev", "probe0")
            remote.stdin.write("setup\n")
            remote.stdin.flush()
            assert remote.stdout.readline().strip() == "configured"
            service = temp / "service"
            service.mkdir(mode=0o700)
            os.chown(service, 1, 1)
            token = secrets.token_hex(32)
            for filename, value in [
                ("token", token),
                ("containment-token", secrets.token_hex(32)),
            ]:
                path = service / filename
                path.write_text(value)
                path.chmod(0o600)
                os.chown(path, 1, 1)
            settings = temp / "airlock.yaml"
            settings.write_text(
                'airlock:\n  enabled: true\n  allowed_destinations: ["https://network-fixture.example/"]\n  allowed_methods: [GET]\ntools:\n  default: allow\n'
            )
            settings.chmod(0o644)
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                port = available.getsockname()[1]
            base = f"http://127.0.0.1:{port}"
            invocation = secrets.token_hex(16)
            controller.service_state = lambda: {
                "ActiveState": "active"
                if process and process.poll() is None
                else "inactive",
                "SubState": "running",
                "InvocationID": invocation,
            }
            env = dict(
                os.environ,
                BIND_ADDR=f"127.0.0.1:{port}",
                POLICY_PATH=str(settings),
                SOURCES_ALLOWLIST_PATH=str(temp / "absent"),
                SERVICE_TOKEN_PATH=str(service / "token"),
                CONTAINMENT_TOKEN_PATH=str(service / "containment-token"),
                AUDIT_LOG_PATH=str(service / "audit.jsonl"),
                AIRLOCK_CONTAINMENT_STATE_PATH=str(service / "containment.json"),
                SSL_CERT_FILE=str(cert),
                INVOCATION_ID=invocation,
                SECAI_NETWORK_BOOT_ID_PATH=str(receipt_dir / "boot-id"),
            )
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def request(path, data=None):
                req = urllib.request.Request(
                    base + path,
                    headers={
                        "Authorization": "Bearer " + token,
                        "Content-Type": "application/json",
                    },
                    data=json.dumps(data).encode() if data is not None else None,
                )
                try:
                    with opener.open(req, timeout=5) as response:
                        return response.status, response.read(4096)
                except urllib.error.HTTPError as error:
                    return error.code, error.read(4096)

            def start():
                output = (temp / "service.log").open("ab")
                child = subprocess.Popen(
                    [
                        "unshare",
                        "--mount",
                        sys.executable,
                        __file__,
                        "--service",
                        str(root),
                        str(controller.resolver_file),
                        str(copied_binary),
                    ],
                    env=env,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                )
                output.close()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    assert child.poll() is None, (temp / "service.log").read_text()
                    try:
                        if request("/health")[0] == 200:
                            return child
                    except OSError:
                        pass
                    time.sleep(0.03)
                raise AssertionError("native airlock startup timeout")

            process = start()
            controller.verify_resolver()
            assert Path("/etc/resolv.conf").read_bytes() == before_global
            checks.append(
                "actual read-only airlock resolver inode verified; global resolver unchanged"
            )
            controller.grant("full_lab", 30)
            status, body = request(
                "/v1/fetch",
                {"destination": "https://network-fixture.example/", "method": "GET"},
            )
            assert status == 200 and body == b"synthetic DNS and TLS response", (
                status,
                body,
            )
            remote.stdin.write("hits\n")
            remote.stdin.flush()
            hits = json.loads(remote.stdout.readline())
            assert hits["dns"] and hits["tls"] == 1
            checks.append("actual native airlock UID direct DNS and verified TLS fetch")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as host_dns:
                host_dns.settimeout(0.2)
                try:
                    host_dns.sendto(b"host DNS remains blocked", ("198.18.0.2", 53))
                except PermissionError:
                    pass
                try:
                    host_dns.recv(64)
                    raise AssertionError("host DNS escaped full lab")
                except TimeoutError:
                    pass
            checks.append("shared root host resolver traffic remains blocked")
            controller.close()
            controller.prepare_resolver()
            try:
                controller.verify_resolver()
                raise AssertionError("old mounted inode accepted after replacement")
            except module.NetworkError:
                pass
            checks.append(
                "already-running airlock old inode rejected after renewal preparation"
            )
            process.terminate()
            process.wait(timeout=5)
            invocation = secrets.token_hex(16)
            env["INVOCATION_ID"] = invocation
            process = start()
            controller.verify_resolver()
            controller.grant("full_lab", 30)
            checks.append(
                "new service invocation and bound inode accepted after restart"
            )
            replacement = uplink.with_suffix(".new")
            replacement.write_bytes(uplink.read_bytes())
            replacement.chmod(0o644)
            replacement.replace(uplink)
            try:
                controller.observe()
                raise AssertionError("replaced uplink source accepted")
            except module.NetworkError:
                pass
            controller.revoke()
            assert controller.observe()["host_offline"] is True
            checks.append(
                "uplink replacement detected; lease revoked without root DNS exception"
            )
            uplink.unlink()
            try:
                controller.verify_resolver()
                raise AssertionError("missing uplink source accepted")
            except FileNotFoundError:
                pass
            checks.append("uplink source removal blocks binding verification")
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            remote.terminate()
            remote.wait(timeout=5)
        print(
            json.dumps(
                {
                    "namespace_isolated": True,
                    "checks": checks,
                    "passed": len(checks),
                    "airlock_sha256": hashlib.sha256(
                        Path(binary).read_bytes()
                    ).hexdigest(),
                    "synthetic_service_uid": 1,
                    "systemd_invocation_query": "fixture adapter; systemd not running",
                }
            )
        )


if __name__ == "__main__":
    if sys.argv[1] == "--peer":
        peer(*sys.argv[2:])
    elif sys.argv[1] == "--service":
        launch_service(*sys.argv[2:])
    else:
        smoke(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
