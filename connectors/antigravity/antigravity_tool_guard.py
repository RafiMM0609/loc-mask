"""Antigravity PreToolUse hook for PII-Shield.

- `run_command` (excluding daemon commands): rewrites CommandLine to run through
  `run_command_mask_wrapper.py` so stdout/stderr are masked before reaching the model.
- `read_file` / `view_file`: returns `decision: "ask"` when targeting sensitive files
  (.env, private keys, credentials) whose output cannot be masked by hooks.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

WRAPPER_SCRIPT = Path(__file__).resolve().with_name("run_command_mask_wrapper.py")
PYTHON_EXE = Path(sys.executable).resolve()

SENSITIVE_EXACT_NAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
    "secrets.yaml",
    "secrets.yml",
    ".npmrc",
    ".pypirc",
    ".netrc",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template")


def _is_sensitive_file(raw_path: str) -> bool:
    name = Path(raw_path.strip()).name.lower()
    if not name:
        return False
    if name in SENSITIVE_EXACT_NAMES:
        return True
    if name.startswith(".env.") and not name.endswith(SAFE_ENV_SUFFIXES):
        return True
    if name.endswith(SENSITIVE_SUFFIXES):
        return True
    if name.startswith("service-account") and name.endswith(".json"):
        return True
    return False


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

    if tool_name in {"read_file", "view_file"}:
        target_path = str(
            args.get("Path") or args.get("AbsolutePath") or args.get("path") or ""
        )
        if _is_sensitive_file(target_path):
            filename = Path(target_path.strip()).name
            print(
                json.dumps(
                    {
                        "decision": "deny",
                        "reason": (
                            f"[PII-Shield] Dilarang membaca '{filename}' lewat {tool_name} karena outputnya tidak termasking. "
                            f"Gunakan run_command (mis. Get-Content -LiteralPath '{target_path}') agar outputnya otomatis dimasking oleh PII-Shield."
                        ),
                    },
                    ensure_ascii=False,
                )
            )
            return 0
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
    py_str = PYTHON_EXE.as_posix()
    wrap_str = WRAPPER_SCRIPT.as_posix()
    if " " in py_str or " " in wrap_str:
        wrapped_cmd = f'& "{py_str}" "{wrap_str}" {encoded_cmd}'
    else:
        wrapped_cmd = f"{py_str} {wrap_str} {encoded_cmd}"

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
