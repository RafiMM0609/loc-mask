"""Redact Codex shell results before they enter model context."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _replace_result(reason: str) -> None:
    print(json.dumps({"decision": "block", "reason": f"[PII-Shield] {reason}"}))


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        original = payload["tool_response"]
        if not isinstance(original, str):
            raise ValueError("Unsupported shell result")
        command = payload["tool_input"]["command"]
        session_id = f"codex-{payload['session_id']}"

        from connectors.antigravity.run_command_mask_wrapper import ENV_COMMAND_RE, _mask_output

        masked = _mask_output(original, session_id=session_id, is_env_command=bool(ENV_COMMAND_RE.search(command)))
    except Exception:
        _replace_result("Output shell ditahan karena PS gagal memeriksanya.")
        return

    if masked != original:
        _replace_result(f"Output shell disamarkan.\n{masked}")


if __name__ == "__main__":
    main()
