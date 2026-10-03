#!/usr/bin/env python3
"""Opt-in field diagnostics. No systemd, sysctl, firewall or package mutations."""
import argparse
import datetime as dt
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time

BASE = Path(__file__).resolve().parents[1]
STATE = BASE / "develop-state"


def private_write(path, text):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing symlink destination")
    fd, name = tempfile.mkstemp(prefix=".ggs-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def run(argv, timeout=8):
    if not shutil.which(str(argv[0])):
        return "SKIP", "Command not installed: " + str(argv[0])
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return ("PASS" if p.returncode == 0 else "FAIL"), (p.stdout + p.stderr)[-65536:]
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or b"") + (e.stderr or b"")
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return "TIMEOUT", output[-65536:]
    except OSError as e:
        return "FAIL", str(e)


def cfg():
    return json.loads((STATE / "config.json").read_text())


def binary():
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise ValueError("Only Linux amd64/arm64 are supported")
    p = BASE / "dist" / ("ggstunnel-linux-" + arch)
    expected = {}
    for line in (BASE / "dist/SHA256SUMS").read_text().splitlines():
        digest, name = line.split()
        expected[name.lstrip("*")] = digest
    if hashlib.sha256(p.read_bytes()).hexdigest() != expected.get(p.name):
        raise ValueError("Binary checksum mismatch")
    p.chmod(0o755)
    return p


def root_required():
    if os.geteuid() != 0:
        raise ValueError("Run with sudo for TUN and raw ICMP")


def prepare():
    if (STATE / "config.json").exists():
        raise ValueError("Config already exists. Edit develop-state/config.json or use another extracted folder")
    role = input("Role [server=Iran / client=foreign]: ").strip()
    if role not in ("server", "client"):
        raise ValueError("Role must be server or client")
    local = str(ipaddress.IPv4Address(input("Local IPv4 assigned to this host: ").strip()))
    peer = str(ipaddress.IPv4Address(input("Peer outer IPv4: ").strip()))
    if local == peer:
        raise ValueError("Local and peer addresses must differ")
    key = getpass.getpass("Shared PSK (same on both; blank on server generates one): ")
    if not key and role == "server":
        key = secrets.token_hex(32)
        print("Copy this PSK privately to the client; it will not be in reports:\n" + key)
    if len(key) < 32 or key.startswith("CHANGE-ME"):
        raise ValueError("Use a shared random PSK of at least 32 characters")
    c = json.loads((BASE / "examples" / (role + ".json")).read_text())
    c["psk"] = key
    c["real"].update(local_ip=local, peer_ip=peer, peer_addr=peer + ":443")
    # Isolate field testing from normal ggs0/ipx interfaces and prior addresses.
    c["tun"].update(name="ggsdev0", local_addr="10.253.77.1" if role == "server" else "10.253.77.2",
                     remote_addr="10.253.77.2" if role == "server" else "10.253.77.1", routes=[])
    c["transport"].update(bip_rto_ms=500, bip_max_retries=6, idle_timeout_sec=300)
    c["telemetry"] = {"interval_sec": 1}
    private_write(STATE / "config.json", json.dumps(c, indent=2) + "\n")
    status, text = run([str(binary()), "-check", "-c", str(STATE / "config.json")])
    if status != "PASS":
        (STATE / "config.json").unlink()
        raise ValueError("Configuration rejected: " + text)
    print(text.strip())


def identity(pid, procroot=Path("/proc")):
    try:
        proc = procroot / str(pid)
        fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            return None
        return {"start": fields[19], "exe": str((proc / "exe").resolve()),
                "argv_hash": hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest()}
    except (OSError, IndexError):
        return None


def owned(name):
    p = STATE / (name + ".pid.json")
    if not p.exists():
        return None
    r = json.loads(p.read_text())
    return r if identity(r["pid"]) == r["identity"] else None


def launch(name, argv):
    if owned(name):
        raise ValueError(name + " is already running")
    path = STATE / (name + ".log")
    if path.is_symlink():
        raise ValueError("Refusing log symlink")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as output:
        p = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    time.sleep(0.5)
    if p.poll() is not None:
        raise ValueError(name + " failed; see " + str(path))
    ident = identity(p.pid)
    if not ident:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)
        raise ValueError("Process exited before registration")
    private_write(STATE / (name + ".pid.json"), json.dumps({"pid": p.pid, "identity": ident}))
    print(name + " started, PID=" + str(p.pid))


def start():
    root_required()
    c = cfg()
    if c["psk"].startswith("CHANGE-ME"):
        raise ValueError("Prepare a real shared PSK first")
    status, output = run([str(binary()), "-check", "-c", str(STATE / "config.json")])
    if status != "PASS":
        raise ValueError(output)
    if run(["ip", "link", "show", "dev", c["tun"]["name"]])[0] == "PASS":
        raise ValueError("TUN name already exists; refusing to reuse it")
    local = run(["ip", "-j", "-4", "addr", "show"])
    if local[0] != "PASS" or not any(
        a.get("local") == c["real"]["local_ip"]
        for row in json.loads(local[1]) for a in row.get("addr_info", [])
    ):
        raise ValueError("real.local_ip is not assigned to this host; NAT needs separate configuration")
    routes = run(["ip", "-j", "-4", "route", "show", "table", "all"])
    if routes[0] != "PASS":
        raise ValueError("Cannot inspect existing routes")
    inner = ipaddress.ip_address(c["tun"]["remote_addr"])
    for row in json.loads(routes[1]):
        prefix = row.get("dst", "default")
        if prefix != "default" and inner in ipaddress.ip_network(prefix, strict=False):
            raise ValueError("Internal test address conflicts with an existing route: " + prefix)
    stats=STATE / "stats.json"
    if stats.is_symlink():
        raise ValueError("Refusing stats symlink")
    stats.unlink(missing_ok=True)
    launch("tunnel", [str(binary()), "-c", str(STATE / "config.json"),
                      "-stats-file", str(STATE / "stats.json")])


def listener(port):
    c = cfg()
    if not owned("tunnel"):
        raise ValueError("Start this bundle's tunnel first")
    if not shutil.which("iperf3"):
        raise ValueError("Install iperf3 first")
    launch("iperf", ["iperf3", "-s", "-B", c["tun"]["local_addr"], "-p", str(port)])
    print("Listener is bound only to the internal IP; stop it after testing.")


def stop(name):
    r = owned(name)
    if not r:
        print(name + ": no matching owned process to stop")
        return
    os.kill(r["pid"], signal.SIGTERM)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and owned(name):
        time.sleep(0.1)
    if owned(name):
        os.kill(r["pid"], signal.SIGKILL)
    (STATE / (name + ".pid.json")).unlink(missing_ok=True)
    print(name + " stopped")


class Report:
    def __init__(self, secret):
        self.secret = secret
        self.parts = []
        self.results = []

    def add(self, label, status, text):
        self.results.append((label, status))
        self.parts.append("\n=== " + label + " [" + status + "] ===\n" + text)
        print(label + ": " + status, flush=True)

    def command(self, label, argv, timeout=8):
        status, output = run(argv, timeout)
        self.add(label, status, "$ " + " ".join(map(str, argv)) + "\n" + output)
        return status

    def save(self, role):
        folder = STATE / "reports"
        folder.mkdir(mode=0o700, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        host = re.sub(r"[^a-zA-Z0-9_-]", "_", socket.gethostname())[:64]
        path = folder / ("ggstunnel-develop-" + role + "-" + host + "-" + stamp + ".txt")
        head = "ggstunnel developer report v1\nUTC=" + stamp + "\n"
        head += "PASS means a command/test completed; it is not production certification.\n"
        head += "\nSUMMARY\n" + "\n".join(label + ": " + status for label, status in self.results) + "\n"
        text = head + "\n".join(self.parts)
        if self.secret:
            text = text.replace(self.secret, "[REDACTED-PSK]")
        private_write(path, text)
        print("REPORT=" + str(path))
        return path


def collect(throughput, port):
    c = cfg()
    r = Report(c.get("psk", ""))
    try:
        safe = {k: c[k] for k in ("role", "profile", "mode", "real", "tun", "transport", "tuner")}
        r.add("Sanitized configuration", "INFO", json.dumps(safe, indent=2))
        r.add("Platform", "INFO", platform.platform() + "\n" + platform.machine())
        r.add("TUN device", "PASS" if Path("/dev/net/tun").exists() else "FAIL", "/dev/net/tun existence")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP):
                pass
            r.add("Raw ICMP capability", "PASS", "Raw socket opened and closed; no packet sent")
        except OSError as e:
            r.add("Raw ICMP capability", "FAIL", str(e))
        r.command("Version and binary checksum", [str(binary()), "-version"])
        r.command("Config validation", [str(binary()), "-check", "-c", str(STATE / "config.json")])
        r.add("Managed tunnel process", "PASS" if owned("tunnel") else "FAIL", str(owned("tunnel")))
        for label, args in (
            ("Address state", ["ip", "-brief", "addr"]),
            ("TUN counters", ["ip", "-s", "link", "show", "dev", c["tun"]["name"]]),
            ("Outer peer route", ["ip", "route", "get", c["real"]["peer_ip"]]),
            ("Inner peer route", ["ip", "route", "get", c["tun"]["remote_addr"]]),
            ("Policy rules", ["ip", "rule", "show"]),
            ("Routes", ["ip", "route", "show", "table", "all"]),
            ("Network sysctls", ["sysctl", "net.ipv4.ip_forward", "net.ipv4.conf.all.rp_filter",
                                   "net.ipv4.icmp_echo_ignore_all", "net.core.rmem_max", "net.core.wmem_max"]),
            ("Outer ICMP echo", ["ping", "-n", "-c", "3", "-W", "2", c["real"]["peer_ip"]]),
            ("Inner small packets", ["ping", "-n", "-I", c["tun"]["name"], "-c", "5", "-W", "2", c["tun"]["remote_addr"]]),
            ("Inner configured MTU", ["ping", "-n", "-I", c["tun"]["name"], "-M", "do", "-s", str(c["tun"]["mtu"]-28), "-c", "3", "-W", "2", c["tun"]["remote_addr"]]),
        ):
            r.command(label, args, 15)
        if throughput:
            status, output = run(["ip", "-j", "route", "get", c["tun"]["remote_addr"]])
            try:
                rows=json.loads(output) if status=="PASS" else []
                correct=bool(rows) and rows[0].get("dev")==c["tun"]["name"]
            except json.JSONDecodeError:
                correct=False
            r.add("Throughput route isolation", "PASS" if correct else "FAIL", output)
            if not correct:
                r.add("Throughput", "SKIP", "Inner peer route is not isolated to the TUN")
            peer = c["tun"]["remote_addr"]
            local = c["tun"]["local_addr"]
            common = ["iperf3", "-c", peer, "-B", local, "-p", str(port), "--connect-timeout", "3000", "-J"]
            for label, extra in (
                ("TCP 2Mbps forward", ["-b", "2M", "-t", "8"]),
                ("TCP 2Mbps reverse", ["-b", "2M", "-t", "8", "-R"]),
                ("UDP 2Mbps forward", ["-u", "-b", "2M", "-l", "1000", "-t", "5"]),
                ("UDP 2Mbps reverse", ["-u", "-b", "2M", "-l", "1000", "-t", "5", "-R"]),
            ):
                if correct:
                    r.command(label, common + extra, 20)
        else:
            r.add("Throughput", "SKIP", "Use test while the peer's listener is running")
        for name in ("stats.json", "tunnel.log", "iperf.log"):
            p = STATE / name
            if p.exists():
                # Tail only; do not load an unbounded long-running log.
                with p.open("rb") as f:
                    f.seek(max(0, p.stat().st_size-32768))
                    text = f.read(32768).decode(errors="replace")
                r.add(name, "INFO", text)
                if name=="stats.json":
                    try:
                        s=json.loads(text)
                        age=(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(s["at"].replace("Z","+00:00"))).total_seconds()
                        r.add("Telemetry freshness", "PASS" if 0<=age<=10 else "FAIL", "Age seconds="+str(round(age,2)))
                        cs=s.get("carrier") or {}
                        observed=cs.get("payload_frame_rx",0)>0 or cs.get("fast_ack_rx",0)>0 or cs.get("pull_probe_rx",0)>0
                        r.add("Authenticated peer traffic observed", "PASS" if observed else "FAIL", "Based on counters since process start")
                    except (ValueError,KeyError,TypeError) as e:
                        r.add("Telemetry parse", "FAIL", str(e))
            else:
                r.add(name, "SKIP", "Not available")
        r.command("Final TUN counters", ["ip", "-s", "link", "show", "dev", c["tun"]["name"]])
    except KeyboardInterrupt:
        r.add("Interrupted", "FAIL", "Partial report saved")
    except (ValueError, OSError) as e:
        r.add("Collector error", "FAIL", str(e))
    finally:
        r.save(c["role"])


def restart_test():
    root_required()
    c=cfg();r=Report(c["psk"])
    if not owned("tunnel"):
        raise ValueError("Start this bundle's tunnel first")
    if owned("iperf"):
        raise ValueError("Run restart-test on the side without the local iperf listener")
    try:
        prerequisite=r.command("Peer reachable before restart",["ping","-n","-I",c["tun"]["name"],"-c","2","-W","2",c["tun"]["remote_addr"]],8)
        if prerequisite!="PASS":
            r.add("Restart prerequisite","FAIL","Peer unreachable; local restart skipped. Start both endpoints first.")
            return
        before=STATE / "stats.json"
        r.add("Before restart telemetry","INFO",before.read_text() if before.exists() else "Unavailable")
        old=owned("tunnel")
        stop("tunnel")
        r.add("Old process stopped","PASS" if not owned("tunnel") else "FAIL",str(old))
        start()
        deadline=time.monotonic()+20
        connected=False
        while time.monotonic()<deadline and owned("tunnel"):
            try:
                s=json.loads((STATE/"stats.json").read_text())
                cs=s.get("carrier") or {}
                connected=cs.get("fast_ack_rx",0)>0 or cs.get("pull_probe_rx",0)>0 or cs.get("payload_frame_rx",0)>0
                if connected:break
            except (OSError,ValueError):
                pass
            time.sleep(0.2)
        r.add("Authenticated reconnect after local restart","PASS" if connected else "FAIL","20-second observation limit")
        r.command("Inner ping after restart",["ping","-n","-I",c["tun"]["name"],"-c","5","-W","2",c["tun"]["remote_addr"]],15)
        for name in ("stats.json","tunnel.log"):
            file=STATE/name
            r.add("After restart "+name,"INFO",file.read_text()[-32768:] if file.exists() else "Unavailable")
    except (OSError,ValueError) as e:
        r.add("Restart failure","FAIL",str(e))
    except KeyboardInterrupt:
        r.add("Interrupted","FAIL","Tunnel may remain running; inspect before retry")
    finally:
        r.save(c["role"])


def do_dispatch(action, port):
    if action == "prepare":
        prepare()
    elif action == "start":
        start()
    elif action == "listen":
        listener(port)
    elif action in ("collect", "test"):
        collect(action == "test", port)
    elif action == "restart-test":
        restart_test()
    elif action == "stop":
        stop("iperf")
        stop("tunnel")


def dispatch(action, port):
    lockpath=STATE / "manager.lock"
    if lockpath.is_symlink():
        raise ValueError("Refusing lock symlink")
    with lockpath.open("a") as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another developer action is running in this folder")
        do_dispatch(action,port)


def main():
    p = argparse.ArgumentParser(description="ggstunnel opt-in developer menu")
    p.add_argument("action", nargs="?", choices=["prepare", "start", "listen", "collect", "test", "stop", "restart-test"])
    p.add_argument("--port", type=int, default=5207)
    args = p.parse_args()
    if not 1024 <= args.port <= 65535:
        p.error("test port must be 1024..65535")
    os.umask(0o077)
    if platform.system() != "Linux":
        p.error("Run this bundle on Linux")
    if STATE.is_symlink():
        p.error("Refusing a symlink state directory")
    STATE.mkdir(mode=0o700, exist_ok=True)
    STATE.chmod(0o700)
    if args.action:
        dispatch(args.action, args.port)
        return
    actions = {"1": "prepare", "2": "start", "3": "listen", "4": "collect", "5": "test", "6": "stop", "7": "restart-test"}
    while True:
        print("\nDEVELOP\n1 Prepare config\n2 Start tunnel\n3 Start internal iperf listener\n4 Collect health report\n5 Run peer TCP/UDP tests + report\n6 Stop owned test processes\n7 Local restart/reconnect test (peer stays running)\n0 Exit (processes remain running)")
        choice = input("Select: ").strip()
        if choice == "0":
            break
        try:
            if choice not in actions:
                raise ValueError("Invalid selection")
            dispatch(actions[choice], args.port)
        except (ValueError, OSError) as e:
            print("ERROR: " + str(e))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as e:
        print("ERROR: " + str(e))
        raise SystemExit(1)
