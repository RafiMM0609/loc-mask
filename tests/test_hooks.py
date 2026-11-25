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
ANTIGRAVITY_TOOL_GUARD = PROJECT_ROOT / "connectors" / "antigravity" / "antigravity_tool_guard.py"
RUN_CMD_WRAPPER = PROJECT_ROOT / "connectors" / "antigravity" / "run_command_mask_wrapper.py"
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


def test_antigravity_tool_guard_rewrites_run_command_and_skips_daemon() -> None:
    res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "Write-Output 'hello'"},
            }
        },
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["decision"] == "allow"
    assert "run_command_mask_wrapper.py" in data["overwrite"]["CommandLine"]

    daemon_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "uvicorn app:app", "IsDaemon": True},
            }
        },
    )
    assert daemon_res.returncode == 0
    assert json.loads(daemon_res.stdout) == {"decision": "allow"}


def test_run_command_mask_wrapper_masks_stdout_and_preserves_exit_code() -> None:
    import base64

    secret = "sk-proj-wrappersecret1234567890abcd"
    out_cmd = "Write-Output" if os.name == "nt" else "echo"
    cmd = f"{out_cmd} 'API_KEY={secret}'; exit 7"
    encoded = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    env = os.environ.copy()
    env["PII_SHIELD_URL"] = "http://127.0.0.1:59999"

    proc = subprocess.run(
        [sys.executable, str(RUN_CMD_WRAPPER), encoded],
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
    )
    assert proc.returncode == 7
    assert secret not in proc.stdout
    assert "<<PII:OPENAI_API_KEY_" in proc.stdout


def test_antigravity_tool_guard_redirects_sensitive_file_reads_to_run_command() -> None:
    env_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "read_file", "args": {"Path": "C:/app/.env"}}},
    )
    assert env_res.returncode == 0
    env_data = json.loads(env_res.stdout)
    assert env_data["decision"] == "deny"
    assert ".env" in env_data["reason"]
    assert "run_command" in env_data["reason"]

    key_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/certs/private.key"}}},
    )
    assert key_res.returncode == 0
    assert json.loads(key_res.stdout)["decision"] == "deny"

    safe_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "read_file", "args": {"Path": "C:/app/.env.example"}}},
    )
    assert safe_res.returncode == 0
    assert json.loads(safe_res.stdout) == {"decision": "allow"}


def test_run_command_mask_wrapper_masks_env_values_including_hosts() -> None:
    import base64

    out_cmd = "Write-Output" if os.name == "nt" else "echo"
    cmd = f"{out_cmd} '# reading .env'; {out_cmd} 'SMTP_HOST=smtp.gmail.com'; {out_cmd} 'PORT=587'; {out_cmd} 'NODE_ENV=production'"
    encoded = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    env = os.environ.copy()
    env["PII_SHIELD_URL"] = "http://127.0.0.1:59999"

    proc = subprocess.run(
        [sys.executable, str(RUN_CMD_WRAPPER), encoded],
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
    )
    assert proc.returncode == 0
    assert "smtp.gmail.com" not in proc.stdout
    assert "SMTP_HOST=<<PII:" in proc.stdout
    assert "PORT=587" in proc.stdout
    assert "NODE_ENV=production" in proc.stdout


def test_run_command_mask_wrapper_detects_env_helper_script_names() -> None:
    import base64

    out_cmd = "Write-Output" if os.name == "nt" else "echo"
    cmd = f"{out_cmd} '# C:/backup-code/check_env.py'; {out_cmd} 'CUSTOM_GATEWAY=gw.internal.local'"
    encoded = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    env = os.environ.copy()
    env["PII_SHIELD_URL"] = "http://127.0.0.1:59999"

    proc = subprocess.run(
        [sys.executable, str(RUN_CMD_WRAPPER), encoded],
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
    )
    assert proc.returncode == 0
    assert "gw.internal.local" not in proc.stdout
    assert "CUSTOM_GATEWAY=<<PII:ENV_VALUE_1>>" in proc.stdout


def test_run_command_mask_wrapper_masks_ps_var_stdout_and_stderr_from_env_file(tmp_path: Path) -> None:
    import base64

    env_file = tmp_path / ".env"
    env_file.write_text(
        'MYSQL_CONNECTION_STRING="mysql+asyncmy://dbuser:SuperPass99@127.0.0.1:3306/db_ai?charset=utf8mb4"\n'
        'MINIO_HOST="localhost:9003"\n'
        "MINIO_ACCESS=minioadminkey\n",
        encoding="utf-8",
    )
    # No quotes around .env, immediately followed by ';' (exact regression pattern)
    cmd = f"$c = Get-Content -Raw {env_file}; Write-Output $c; [Console]::Error.WriteLine($c)"
    encoded = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    env = os.environ.copy()
    env["PII_SHIELD_URL"] = "http://127.0.0.1:59999"

    proc = subprocess.run(
        [sys.executable, str(RUN_CMD_WRAPPER), encoded],
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
    )
    assert proc.returncode == 0
    for stream in (proc.stdout, proc.stderr):
        assert "SuperPass99" not in stream
        assert "minioadminkey" not in stream
        assert "localhost:9003" not in stream
        assert "<<PII:" in stream
