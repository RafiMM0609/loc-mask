"""Executes a base64-encoded shell command and masks secrets/PII in stdout and stderr."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PII_SHIELD_URL = os.environ.get("PII_SHIELD_URL", "http://127.0.0.1:8787").rstrip("/")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SERVER_AVAILABLE: bool | None = None
_FALLBACK_CTX: tuple[object, object] | None = None
_FALLBACK_VALUE_MAP: dict[tuple[str, str], str] = {}
_FALLBACK_COUNTERS: dict[str, int] = {}
_ENV_VALUE_MAP: dict[str, str] = {}
_ENV_COUNTER: int = 0
ENV_COMMAND_RE = re.compile(
    r"(?:^|[\s'\"/\\(=,;])(?:\.env(?!\.(?:example|sample|template)(?![A-Za-z0-9_.-]))(?:\.[A-Za-z0-9_.-]+)?|[A-Za-z0-9_.-]*env[A-Za-z0-9_.-]*\.(?:py|ps1|sh|js|ts|cmd|bat))(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
ENV_LINE_RE = re.compile(r"^(?P<prefix>\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(?P<val>.+?)\s*$")
SAFE_ENV_LITERALS = {"true", "false", "null", "none", "undefined", "development", "production", "staging", "local", "test"}


def _mask_via_server(text: str, session_id: str) -> str | None:
    global _SERVER_AVAILABLE
    if not text:
        return text
    if _SERVER_AVAILABLE is False:
        return None
    req = urllib.request.Request(
        f"{PII_SHIELD_URL}/api/v1/mask",
        data=json.dumps({"text": text, "session_id": session_id}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=0.8) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            masked = payload.get("text")
            _SERVER_AVAILABLE = True
            return str(masked) if masked is not None else text
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        _SERVER_AVAILABLE = False
        return None


def _get_fallback_ctx() -> tuple[object, object]:
    global _FALLBACK_CTX
    if _FALLBACK_CTX is None:
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
        _FALLBACK_CTX = (cfg, scanner)
    return _FALLBACK_CTX


def _mask_offline_fallback(text: str) -> str:
    if not text:
        return text
    cfg, scanner = _get_fallback_ctx()
    matches = scanner.scan(text)
    if not matches:
        return text

    parts: list[str] = []
    cursor = 0
    for m in matches:
        if m.start < cursor:
            continue
        raw_val = text[m.start : m.end]
        key = (m.entity_type, raw_val)
        placeholder = _FALLBACK_VALUE_MAP.get(key)
        if placeholder is None:
            _FALLBACK_COUNTERS[m.entity_type] = _FALLBACK_COUNTERS.get(m.entity_type, 0) + 1
            placeholder = (
                f"{cfg.masking.placeholder_prefix}{m.entity_type}_"
                f"{_FALLBACK_COUNTERS[m.entity_type]}{cfg.masking.placeholder_suffix}"
            )
            _FALLBACK_VALUE_MAP[key] = placeholder
        parts.append(text[cursor : m.start])
        parts.append(placeholder)
        cursor = m.end
    parts.append(text[cursor:])
    return "".join(parts)


def _mask_env_lines(text: str) -> str:
    global _ENV_COUNTER
    if not text:
        return text
    out_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        ending = ""
        if line.endswith("\r\n"):
            body, ending = line[:-2], "\r\n"
        elif line.endswith("\n"):
            body, ending = line[:-1], "\n"
        else:
            body = line

        m = ENV_LINE_RE.match(body)
        if m:
            val = m.group("val").strip()
            unquoted = val.strip("'\"")
            if (
                unquoted
                and "<<PII:" not in val
                and unquoted.lower() not in SAFE_ENV_LITERALS
                and not unquoted.isdigit()
            ):
                placeholder = _ENV_VALUE_MAP.get(unquoted)
                if placeholder is None:
                    _ENV_COUNTER += 1
                    placeholder = f"<<PII:ENV_VALUE_{_ENV_COUNTER}>>"
                    _ENV_VALUE_MAP[unquoted] = placeholder
                out_lines.append(f"{m.group('prefix')}{placeholder}{ending}")
                continue
        out_lines.append(line)
    return "".join(out_lines)


def _mask_output(text: str, session_id: str, is_env_command: bool = False) -> str:
    if not text:
        return text
    masked = _mask_via_server(text, session_id=session_id)
    if masked is None:
        masked = _mask_offline_fallback(text)
    if is_env_command:
        masked = _mask_env_lines(masked)
    return masked


def _run_original_command(command_line: str) -> subprocess.CompletedProcess[bytes]:
    if os.name == "nt":
        shell = shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"
        utf16_b64 = base64.b64encode(command_line.encode("utf-16le")).decode("ascii")
        return subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-EncodedCommand", utf16_b64],
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

    session_id = (
        sys.argv[2].strip()
        if len(sys.argv) >= 3 and sys.argv[2].strip()
        else os.environ.get("PII_SHIELD_SESSION", "agy-run-command")
    )
    is_env_cmd = bool(ENV_COMMAND_RE.search(command_line))
    proc = _run_original_command(command_line)

    stdout_text = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
    stderr_text = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""

    if stdout_text:
        sys.stdout.write(_mask_output(stdout_text, session_id=session_id, is_env_command=is_env_cmd))
        sys.stdout.flush()
    if stderr_text:
        sys.stderr.write(_mask_output(stderr_text, session_id=session_id, is_env_command=is_env_cmd))
        sys.stderr.flush()

    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
