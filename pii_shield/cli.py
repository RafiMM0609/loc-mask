"""CLI manager for starting, stopping, inspecting, and testing PII-Shield."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx
import uvicorn

from pii_shield.config import PROJECT_ROOT, load_config

RUN_DIR = PROJECT_ROOT / ".run"
PID_FILE = RUN_DIR / "server.pid"
LOG_FILE = RUN_DIR / "server.log"


def _is_pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return exit_code.value == STILL_ACTIVE
            return False
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        data = json.loads(PID_FILE.read_text(encoding="utf-8"))
        pid = int(data["pid"])
        return pid if _is_pid_running(pid) else None
    except Exception:
        return None


def _health_check(host: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        with httpx.Client(trust_env=False, timeout=timeout) as client:
            resp = client.get(f"http://{host}:{port}/health")
        if resp.status_code == 200:
            return resp.json()
    except httpx.RequestError:
        return None
    return None


def cmd_start(args: argparse.Namespace) -> int:
    cfg = load_config()
    host = args.host or cfg.server.host
    port = args.port or cfg.server.port

    if args.foreground:
        uvicorn.run(
            "pii_shield.server:app",
            host=host,
            port=port,
            log_level=cfg.server.log_level,
        )
        return 0

    existing_health = _health_check(host, port)
    if existing_health:
        print(f"PII-Shield sudah berjalan di http://{host}:{port} (status: {existing_health['status']})")
        return 0

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "pii_shield.cli",
        "start",
        "--foreground",
        "--host",
        host,
        "--port",
        str(port),
    ]

    base_flags = 0
    if os.name == "nt":
        base_flags = (
            getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        )

    def _spawn(creationflags: int) -> subprocess.Popen[bytes]:
        with open(LOG_FILE, "a", encoding="utf-8") as log_fp:
            return subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                stdout=log_fp,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
                close_fds=True,
            )

    if os.name == "nt":
        breakaway = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)
        try:
            proc = _spawn(base_flags | breakaway)
        except OSError:
            proc = _spawn(base_flags)
    else:
        proc = _spawn(base_flags)

    PID_FILE.write_text(
        json.dumps({"pid": proc.pid, "host": host, "port": port}, indent=2),
        encoding="utf-8",
    )

    deadline = time.monotonic() + 25.0
    while time.monotonic() < deadline:
        info = _health_check(host, port, timeout=0.5)
        if info:
            print(f"[OK] PII-Shield berjalan di background (PID={proc.pid}) -> http://{host}:{port}")
            return 0
        if not _is_pid_running(proc.pid):
            break
        time.sleep(0.25)

    print(f"[ERROR] Gagal memulai PII-Shield. Cek log di: {LOG_FILE}", file=sys.stderr)
    return 1


def cmd_stop(args: argparse.Namespace) -> int:
    pid = _read_pid()
    if pid is None:
        if PID_FILE.exists():
            PID_FILE.unlink(missing_ok=True)
        print("PII-Shield tidak sedang berjalan.")
        return 0

    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pass
    else:
        os.kill(pid, signal.SIGTERM)

    PID_FILE.unlink(missing_ok=True)
    print(f"[OK] PII-Shield (PID={pid}) telah dihentikan.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = load_config()
    host = cfg.server.host
    port = cfg.server.port
    pid = _read_pid()
    info = _health_check(host, port)

    if info:
        print(f"Status      : RUNNING (PID={pid or 'external'})")
        print(f"Endpoint    : http://{host}:{port}")
        print(f"Codex Proxy : http://{host}:{port}/chatgpt-backend/ (atau /openai/v1)")
        print(f"Vault       : {info.get('active_placeholders', 0)} active placeholder(s)")
        return 0

    print("Status      : STOPPED")
    print(f"Target      : http://{host}:{port}")
    return 1


def cmd_test(args: argparse.Namespace) -> int:
    cfg = load_config()
    host = cfg.server.host
    port = cfg.server.port
    text = args.text

    info = _health_check(host, port)
    if info:
        base = f"http://{host}:{port}"
        with httpx.Client(trust_env=False, timeout=5.0) as client:
            masked = client.post(
                f"{base}/api/v1/mask",
                json={"text": text, "session_id": "cli-test"},
            ).json()
            unmasked = client.post(
                f"{base}/api/v1/unmask",
                json={"text": masked["text"], "session_id": "cli-test"},
            ).json()
        print("Mode        : Live Server")
        print(f"Input       : {text}")
        print(f"Detected    : {masked['entity_types']}")
        print(f"Masked      : {masked['text']}")
        print(f"Unmasked    : {unmasked['text']}")
        return 0

    from pii_shield.engine import MaskingEngine

    engine = MaskingEngine(cfg)
    masked_res = engine.mask_text(text, session_id="cli-test")
    unmasked_text, _ = engine.unmask_text(masked_res.text, session_id="cli-test")
    print("Mode        : Local Engine (server offline)")
    print(f"Input       : {text}")
    print(f"Detected    : {masked_res.entity_types}")
    print(f"Masked      : {masked_res.text}")
    print(f"Unmasked    : {unmasked_text}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="pii-shield", description="PII-Shield CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start", help="Start PII-Shield server")
    p_start.add_argument("--foreground", action="store_true", help="Run in foreground")
    p_start.add_argument("--host", default=None)
    p_start.add_argument("--port", type=int, default=None)
    p_start.set_defaults(func=cmd_start)

    p_stop = sub.add_parser("stop", help="Stop background PII-Shield server")
    p_stop.set_defaults(func=cmd_stop)

    p_status = sub.add_parser("status", help="Check PII-Shield server status")
    p_status.set_defaults(func=cmd_status)

    p_test = sub.add_parser("test", help="Test masking & unmasking roundtrip")
    p_test.add_argument("text", help="Text to test")
    p_test.set_defaults(func=cmd_test)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
