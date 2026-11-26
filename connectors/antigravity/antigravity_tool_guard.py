"""Antigravity PreToolUse hook for PII-Shield.

- `run_command` (excluding daemon commands): rewrites CommandLine to run through
  `run_command_mask_wrapper.py` (forwarding `agy-<conversationId>` as session_id)
  so stdout/stderr are masked before reaching the model.
- `read_file` / `view_file` / `view_file_outline` / `view_code_item`: returns
  `decision: "deny"` when targeting sensitive credential files or config/data/log
  files containing detected secrets or PII whose output cannot be masked by hooks.
- `grep_search`: returns `decision: "deny"` when targeting sensitive files,
  sensitive include globs, or scannable config/data/log files containing secrets/PII.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

WRAPPER_SCRIPT = Path(__file__).resolve().with_name("run_command_mask_wrapper.py")
PYTHON_EXE = Path(sys.executable)
PII_SHIELD_URL = os.environ.get("PII_SHIELD_URL", "http://127.0.0.1:8787").rstrip("/")
PROJECT_ROOT = Path(__file__).resolve().parents[2]

SENSITIVE_EXACT_NAMES = {
    ".env",
    ".envrc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
    "secrets.yaml",
    "secrets.yml",
    "secrets.json",
    "secrets.toml",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    ".htpasswd",
    "kubeconfig",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ovpn")
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")
SCANNABLE_DATA_SUFFIXES = {
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".xml",
    ".csv",
    ".tsv",
    ".log",
    ".sql",
    ".dump",
}
_MAX_SCAN_BYTES = 262_144
_DEFAULT_MAX_LINES = 800


def _is_sensitive_file(raw_path: str) -> bool:
    norm = raw_path.strip().replace("\\", "/")
    if not norm:
        return False
    low_norm = norm.lower()
    name = Path(norm).name.lower()
    if not name:
        return False
    if name in SENSITIVE_EXACT_NAMES:
        return True
    if name.startswith(".env.") and not name.endswith(SAFE_ENV_SUFFIXES):
        return True
    if name.endswith(SENSITIVE_SUFFIXES):
        return True
    if (name.startswith("service-account") or name.startswith("client_secret")) and name.endswith(".json"):
        return True
    if low_norm.endswith(("/.aws/credentials", "/.kube/config")) or low_norm in {"aws/credentials", "kube/config"}:
        return True
    return False


def _is_sensitive_include(pattern: str) -> bool:
    norm = pattern.strip().replace("\\", "/")
    if not norm:
        return False
    if _is_sensitive_file(norm):
        return True
    tail = norm.rsplit("/", 1)[-1].lstrip("*")
    if not tail:
        return False
    if _is_sensitive_file(tail):
        return True
    low_tail = tail.lower()
    if low_tail.startswith(".env") and not low_tail.endswith(SAFE_ENV_SUFFIXES):
        return True
    return False


def _resolve_target_path(raw_path: str, cwd: str) -> Path:
    candidate = Path(raw_path.strip())
    if not candidate.is_absolute() and cwd.strip():
        return Path(cwd.strip()) / candidate
    return candidate


def _read_slice_for_scan(path: Path, args: dict) -> str:
    raw_start = args.get("StartLine")
    raw_end = args.get("EndLine")
    start_line = raw_start if isinstance(raw_start, int) and raw_start >= 1 else 1
    end_line = (
        raw_end
        if isinstance(raw_end, int) and raw_end >= start_line
        else start_line + _DEFAULT_MAX_LINES - 1
    )

    chunks: list[str] = []
    total_bytes = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                if line_no < start_line:
                    continue
                if line_no > end_line:
                    break
                total_bytes += len(line.encode("utf-8", errors="replace"))
                if total_bytes > _MAX_SCAN_BYTES:
                    remaining = _MAX_SCAN_BYTES - (total_bytes - len(line.encode("utf-8", errors="replace")))
                    if remaining > 0:
                        chunks.append(line[:remaining])
                    break
                chunks.append(line)
    except OSError:
        return ""
    return "".join(chunks)


def _scan_via_server(text: str) -> list[str] | None:
    req = urllib.request.Request(
        f"{PII_SHIELD_URL}/api/v1/scan",
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=0.4) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            if payload.get("has_sensitive"):
                return list(payload.get("entity_types") or [])
            return []
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def _scan_offline_fallback(text: str) -> list[str]:
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
    seen: list[str] = []
    for match in scanner.scan(text):
        if match.entity_type not in seen:
            seen.append(match.entity_type)
    return seen


def _scan_data_file_if_applicable(raw_path: str, cwd: str, args: dict) -> list[str]:
    if not raw_path.strip():
        return []
    resolved = _resolve_target_path(raw_path, cwd)
    name_low = resolved.name.lower()
    if name_low.endswith(SAFE_ENV_SUFFIXES):
        return []
    if resolved.suffix.lower() not in SCANNABLE_DATA_SUFFIXES:
        return []
    try:
        if not resolved.is_file():
            return []
    except OSError:
        return []

    text = _read_slice_for_scan(resolved, args)
    if not text.strip():
        return []

    detected = _scan_via_server(text)
    if detected is None:
        detected = _scan_offline_fallback(text)
    return detected


def _deny_response(reason: str) -> int:
    print(json.dumps({"decision": "deny", "reason": reason}, ensure_ascii=False))
    return 0


def main() -> int:
    try:
        raw_stdin = sys.stdin.read()
        payload = json.loads(raw_stdin) if raw_stdin.strip() else {}
    except json.JSONDecodeError:
        print(json.dumps({"decision": "allow"}))
        return 0

    tool_call = payload.get("toolCall") or {}
    tool_name = tool_call.get("name")
    args = tool_call.get("args") or {}
    cwd = str(payload.get("cwd") or "")

    if tool_name in {"read_file", "view_file", "view_file_outline", "view_code_item"}:
        target_path = str(
            args.get("Path") or args.get("AbsolutePath") or args.get("File") or args.get("path") or ""
        )
        if _is_sensitive_file(target_path):
            filename = Path(target_path.strip()).name
            return _deny_response(
                f"[PII-Shield] Dilarang membaca '{filename}' lewat {tool_name} karena outputnya tidak termasking. "
                f"Gunakan run_command (mis. Get-Content -LiteralPath '{target_path}') agar outputnya otomatis dimasking oleh PII-Shield."
            )
        detected_types = _scan_data_file_if_applicable(target_path, cwd, args)
        if detected_types:
            filename = Path(target_path.strip()).name
            summary = ", ".join(detected_types)
            return _deny_response(
                f"[PII-Shield] Dilarang membaca '{filename}' lewat {tool_name} karena terdeteksi data sensitif ({summary}) "
                f"dan output {tool_name} tidak termasking. Gunakan run_command (mis. Get-Content -LiteralPath '{target_path}') "
                f"agar outputnya otomatis dimasking oleh PII-Shield."
            )
        print(json.dumps({"decision": "allow"}))
        return 0

    if tool_name == "grep_search":
        search_target = str(
            args.get("SearchPath")
            or args.get("SearchDirectory")
            or args.get("Path")
            or args.get("Directory")
            or ""
        ).strip()
        if _is_sensitive_file(search_target):
            filename = Path(search_target).name
            return _deny_response(
                f"[PII-Shield] Dilarang mencari di '{filename}' lewat grep_search karena outputnya tidak termasking. "
                f"Gunakan run_command (mis. Select-String / rg) agar outputnya otomatis dimasking oleh PII-Shield."
            )

        includes_raw = args.get("Includes")
        includes: list[str] = []
        if isinstance(includes_raw, str):
            includes = [includes_raw]
        elif isinstance(includes_raw, list):
            includes = [str(item) for item in includes_raw if isinstance(item, str)]
        if any(_is_sensitive_include(pattern) for pattern in includes):
            return _deny_response(
                "[PII-Shield] Dilarang menjalankan grep_search dengan filter Includes ke file sensitif karena outputnya tidak termasking. "
                "Gunakan run_command (mis. Select-String / rg) agar outputnya otomatis dimasking oleh PII-Shield."
            )

        detected_types = _scan_data_file_if_applicable(search_target, cwd, {})
        if detected_types:
            filename = Path(search_target).name
            summary = ", ".join(detected_types)
            return _deny_response(
                f"[PII-Shield] Dilarang mencari di '{filename}' lewat grep_search karena terdeteksi data sensitif ({summary}) "
                f"dan output grep_search tidak termasking. Gunakan run_command (mis. Select-String / rg) "
                f"agar outputnya otomatis dimasking oleh PII-Shield."
            )
        print(json.dumps({"decision": "allow"}))
        return 0

    if tool_name != "run_command":
        print(json.dumps({"decision": "allow"}))
        return 0

    if args.get("IsDaemon"):
        print(json.dumps({"decision": "allow"}))
        return 0

    cmd_line = args.get("CommandLine")
    if not isinstance(cmd_line, str) or not cmd_line.strip():
        print(json.dumps({"decision": "allow"}))
        return 0

    if "run_command_mask_wrapper.py" in cmd_line:
        print(json.dumps({"decision": "allow"}))
        return 0

    encoded_cmd = base64.b64encode(cmd_line.encode("utf-8")).decode("ascii")
    raw_conv = str(payload.get("conversationId") or "").strip()
    clean_conv = re.sub(r"[^A-Za-z0-9_.-]", "", raw_conv)[:64]
    session_arg = f"agy-{clean_conv}" if clean_conv else ""

    py_str = PYTHON_EXE.as_posix()
    wrap_str = WRAPPER_SCRIPT.as_posix()
    if " " in py_str or " " in wrap_str:
        wrapped_cmd = f'& "{py_str}" "{wrap_str}" {encoded_cmd}'
        if session_arg:
            wrapped_cmd += f' "{session_arg}"'
    else:
        wrapped_cmd = f"{py_str} {wrap_str} {encoded_cmd}"
        if session_arg:
            wrapped_cmd += f" {session_arg}"

    print(
        json.dumps(
            {
                "decision": "allow",
                "overwrite": {
                    "CommandLine": wrapped_cmd,
                },
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
