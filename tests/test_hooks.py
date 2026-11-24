"""Subprocess tests for Antigravity and Codex hook guard scripts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ANTIGRAVITY_GUARD = PROJECT_ROOT / "connectors" / "antigravity" / "antigravity_guard.py"
CODEX_GUARD = PROJECT_ROOT / "connectors" / "codex" / "codex_hook_guard.py"


def _run_guard(script: Path, payload: dict, env_extra: dict[str, str] | None = None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env,
        timeout=10,
    )


def test_antigravity_guard_offline_fallback_blocks_leak_and_allows_clean() -> None:
    offline_env = {"PII_SHIELD_URL": "http://127.0.0.1:59999"}

    res_clean = _run_guard(
        ANTIGRAVITY_GUARD,
        {"lastUserInput": "Tolong jelaskan cara kerja FastAPI middleware"},
        env_extra=offline_env,
    )
    assert res_clean.returncode == 0
    assert json.loads(res_clean.stdout) == {"terminationBehavior": ""}

    secret = "sk-proj-antigravityleaktest1234567890"
    res_leak = _run_guard(
        ANTIGRAVITY_GUARD,
        {"lastUserInput": f"Debug key ini: {secret} dan NIK 3273011508950001"},
        env_extra=offline_env,
    )
    assert res_leak.returncode == 0
    data = json.loads(res_leak.stdout)
    assert data["terminationBehavior"] == "terminate"
    msg = data["injectSteps"][0]["errorMessage"]["userMessage"]
    assert "OPENAI_API_KEY" in msg
    assert "ID_NIK" in msg
    assert secret not in msg
    assert "3273011508950001" not in msg


def test_antigravity_guard_live_server_mode() -> None:
    class _ScanHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"has_sensitive": True, "count": 1, "entity_types": ["DB_URI"], "entities": []}
                ).encode("utf-8")
            )

        def log_message(self, format, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _ScanHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        res = _run_guard(
            ANTIGRAVITY_GUARD,
            {"lastUserInput": "postgres://u:p@host:5432/db"},
            env_extra={"PII_SHIELD_URL": f"http://127.0.0.1:{port}"},
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["terminationBehavior"] == "terminate"
        assert "DB_URI" in data["injectSteps"][0]["errorMessage"]["userMessage"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_codex_hook_guard_exit_codes() -> None:
    offline_env = {"PII_SHIELD_URL": "http://127.0.0.1:59999"}
    ok = _run_guard(CODEX_GUARD, {"prompt": "Refactor unit tests"}, env_extra=offline_env)
    assert ok.returncode == 0

    blocked = _run_guard(
        CODEX_GUARD,
        {"prompt": "Gunakan token ghp_1234567890abcdefghijklmnopqrstuvwxyz"},
        env_extra=offline_env,
    )
    assert blocked.returncode == 2
    assert "GITHUB_TOKEN" in blocked.stderr
