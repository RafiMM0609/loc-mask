"""Ensure the shared masking server is ready before Codex sends a request."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pii_shield.cli import _health_check, cmd_start
from pii_shield.config import load_config


def main() -> None:
    cfg = load_config()
    host, port = cfg.server.host, cfg.server.port
    health = _health_check(host, port)
    if health and health.get("service") == "pii-shield":
        return
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        cmd_start(argparse.Namespace(host=host, port=port, foreground=False))
    health = _health_check(host, port)
    if not health or health.get("service") != "pii-shield":
        print(json.dumps({
            "decision": "block",
            "reason": "[PII-Shield] Server masking gagal dimulai. Periksa .run/server.log.",
        }))


if __name__ == "__main__":
    sys.stdin.read()  # Drain hook input; prompt text is masked by the proxy.
    main()
