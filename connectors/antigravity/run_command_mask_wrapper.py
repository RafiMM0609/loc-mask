"""Executes a base64-encoded shell command and masks secrets/PII in stdout and stderr."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PII_SHIELD_URL = os.environ.get("PII_SHIELD_URL", "http://127.0.0.1:8787").rstrip("/")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _mask_via_server(text: str, session_id: str) -> str | None:
    if not text:
        return text
    req = urllib.request.Request(
        f"{PII_SHIELD_URL}/api/v1/mask",
        data=json.dumps({"text": text, "session_id": session_id}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=1.5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            masked = payload.get("text")
            return str(masked) if masked is not None else text
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def _mask_offline_fallback(text: str) -> str:
    if not text:
        return text
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from pii_shield.config import load_config
    from pii_shield.patterns import FastRegexFallbackScanner

    cfg = load_config()
    scanner = FastRegexFallbackScanner(
        detect_secrets=cfg.masking.detect_secrets,
        detect_pii=cfg.masking.detect_pii,
        allowlist_values=cfg.allowlist_values,
    )
    matches = scanner.scan(text)
    if not matches:
        return text

    out = text
    counters: dict[str, int] = {}
    for m in reversed(matches):
        counters[m.entity_type] = counters.get(m.entity_type, 0) + 1
        placeholder = f"{cfg.masking.placeholder_prefix}{m.entity_type}_{counters[m.entity_type]}{cfg.masking.placeholder_suffix}"
        out = out[: m.start] + placeholder + out[m.end :]
    return out


def _mask_output(text: str, session_id: str) -> str:
    if not text:
        return text
    masked = _mask_via_server(text, session_id=session_id)
    if masked is not None:
        return masked
    return _mask_offline_fallback(text)


def _run_original_command(command_line: str) -> subprocess.CompletedProcess[bytes]:
    if os.name == "nt":
        shell = shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"
        utf16_b64 = base64.b64encode(command_line.encode("utf-16le")).decode("ascii")
        return subprocess.run(
            [shell, "-NoProfile", "-EncodedCommand", utf16_b64],
            capture_output=True,
        )
    shell = shutil.which("bash") or "/bin/sh"
    return subprocess.run([shell, "-c", command_line], capture_output=True)


def main() -> int:
    if len(sys.argv) < 2:
        print("[PII-Shield] Missing encoded command argument.", file=sys.stderr)
        return 2

    try:
        command_line = base64.b64decode(sys.argv[1]).decode("utf-8")
    except Exception as exc:
        print(f"[PII-Shield] Invalid encoded command: {exc}", file=sys.stderr)
        return 2

    session_id = os.environ.get("PII_SHIELD_SESSION", "agy-run-command")
    proc = _run_original_command(command_line)

    stdout_text = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
    stderr_text = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""

    if stdout_text:
        sys.stdout.write(_mask_output(stdout_text, session_id=session_id))
        sys.stdout.flush()
    if stderr_text:
        sys.stderr.write(_mask_output(stderr_text, session_id=session_id))
        sys.stderr.flush()

    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
