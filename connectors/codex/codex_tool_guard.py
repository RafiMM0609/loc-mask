"""Mask shell output using the same server/regex wrapper as Antigravity."""

from __future__ import annotations

import base64
import json
import re
import shlex
import sys
from pathlib import Path

WRAPPER = Path(__file__).resolve().parents[1] / "antigravity" / "run_command_mask_wrapper.py"


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        tool_input = payload["tool_input"]
        command = tool_input["command"]
        if not isinstance(command, str) or not command.strip() or WRAPPER.name in command:
            return
    except (ValueError, KeyError, TypeError, AttributeError):
        return

    raw_session = str(payload.get("session_id") or "").strip()
    clean_session = re.sub(r"[^A-Za-z0-9_.-]", "", raw_session)[:64]
    session_id = f"codex-{clean_session}" if clean_session else "codex-bash"

    encoded = base64.b64encode(command.encode("utf-8")).decode("ascii")
    # Hook shell inputs use the session's shell; pass session_id to the shared wrapper.
    if sys.platform == "win32":
        quote = lambda value: "'" + value.replace("'", "''") + "'"
        replacement = f"& {quote(sys.executable)} {quote(str(WRAPPER))} {encoded} {quote(session_id)}; exit $LASTEXITCODE"
    else:
        replacement = f"{shlex.quote(sys.executable)} {shlex.quote(str(WRAPPER))} {encoded} {shlex.quote(session_id)}"

    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {**tool_input, "command": replacement},
                }
            }
        )
    )


if __name__ == "__main__":
    main()
