"""Subprocess tests for Antigravity and Codex hook guard scripts."""

from __future__ import annotations

import io
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
CODEX_PROMPT_GUARD = PROJECT_ROOT / "connectors" / "codex" / "codex_hook_guard.py"
CODEX_OUTPUT_GUARD = PROJECT_ROOT / "connectors" / "codex" / "codex_shell_output_guard.py"


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


def test_codex_shell_masks_tool_result_and_preserves_exit_status() -> None:
    synthetic = "sk-proj-" + "syntheticcodextest1234567890"
    payload = {
        "session_id": "test-session",
        "tool_input": {"command": "Get-Content .env"},
        "tool_response": f"Process exited with code 7\nOutput:\nCUSTOM_GATEWAY=private.internal.example\n{synthetic}",
    }
    env = {"PII_SHIELD_URL": "http://127.0.0.1:59999"}
    replaced = _run_guard(CODEX_OUTPUT_GUARD, payload, env)
    feedback = json.loads(replaced.stdout)
    assert replaced.returncode == 0
    assert feedback["decision"] == "block"
    assert "exited with code 7" in feedback["reason"]
    assert "private.internal.example" not in feedback["reason"]
    assert synthetic not in feedback["reason"]
    assert "<<PII:" in feedback["reason"]

    payload["tool_response"] = "Process exited with code 0\nOutput:\nPlain text"
    clean = _run_guard(CODEX_OUTPUT_GUARD, payload, env)
    assert clean.returncode == 0
    assert clean.stdout == ""


def test_codex_shell_holds_unrecognized_result() -> None:
    result = _run_guard(CODEX_OUTPUT_GUARD, {"tool_response": {"private detail": "synthetic input"}})
    assert result.returncode == 0
    assert json.loads(result.stdout)["decision"] == "block"
    assert "synthetic input" not in result.stdout + result.stderr


def test_codex_prompt_guard_uses_local_fallback() -> None:
    env = {"PII_SHIELD_URL": "http://127.0.0.1:59999"}
    clean = _run_guard(CODEX_PROMPT_GUARD, {"prompt": "Explain middleware"}, env)
    assert clean.returncode == 0
    assert clean.stdout == ""

    synthetic = "sk-proj-" + "syntheticcodexprompt1234567890"
    blocked = _run_guard(CODEX_PROMPT_GUARD, {"prompt": f"Debug {synthetic}"}, env)
    assert blocked.returncode == 0
    assert json.loads(blocked.stdout)["decision"] == "block"
    assert "OPENAI_API_KEY" in blocked.stdout
    assert synthetic not in blocked.stdout + blocked.stderr


def test_codex_prompt_guard_blocks_when_scanner_fails(monkeypatch, capsys) -> None:
    from connectors.codex import codex_hook_guard as guard

    monkeypatch.setattr(guard, "_scan_via_server", lambda *_: None)

    def unavailable(*args):
        raise RuntimeError("private detail")

    monkeypatch.setattr(guard, "_scan_offline", unavailable)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"prompt": "synthetic input"}'))
    guard.main()
    output = capsys.readouterr().out
    assert json.loads(output)["decision"] == "block"
    assert "scanner tidak tersedia" in output
    assert "private detail" not in output
    assert "synthetic input" not in output


def test_codex_prompt_guard_uses_live_scan(tmp_path: Path) -> None:
    requests = []

    class ScanHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, json.loads(body)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"has_sensitive":true,"entity_types":["PERSON"]}')

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), ScanHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "config.yaml"
    config.write_text(f"server:\n  port: {server.server_port}\n", encoding="utf-8")
    try:
        result = _run_guard(CODEX_PROMPT_GUARD, {"prompt": "Synthetic Person"}, {
            "PII_SHIELD_CONFIG": str(config), "PII_SHIELD_URL": "",
        })
        assert result.returncode == 0
        assert json.loads(result.stdout)["decision"] == "block"
        assert "PERSON" in result.stdout
        assert "Synthetic Person" not in result.stdout + result.stderr
        assert requests == [("/api/v1/scan", {"text": "Synthetic Person"})]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


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


def test_antigravity_tool_guard_blocks_grep_search_on_sensitive_targets_and_allows_normal() -> None:
    env_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "grep_search", "args": {"SearchPath": "C:/app/.env", "Query": "SECRET"}}},
    )
    assert env_res.returncode == 0
    assert json.loads(env_res.stdout)["decision"] == "deny"

    inc_env_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {
            "toolCall": {
                "name": "grep_search",
                "args": {"SearchPath": "C:/app", "Query": "KEY", "Includes": [".env*"]},
            }
        },
    )
    assert inc_env_res.returncode == 0
    assert json.loads(inc_env_res.stdout)["decision"] == "deny"

    inc_pem_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {
            "toolCall": {
                "name": "grep_search",
                "args": {"SearchPath": "C:/app", "Query": "BEGIN", "Includes": ["*.pem"]},
            }
        },
    )
    assert inc_pem_res.returncode == 0
    assert json.loads(inc_pem_res.stdout)["decision"] == "deny"

    ok_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {
            "toolCall": {
                "name": "grep_search",
                "args": {"SearchPath": "C:/app/src", "Query": "def main", "Includes": ["*.py"]},
            }
        },
    )
    assert ok_res.returncode == 0
    assert json.loads(ok_res.stdout) == {"decision": "allow"}


def test_antigravity_tool_guard_scans_config_and_data_files_on_read(tmp_path: Path) -> None:
    offline_env = {"PII_SHIELD_URL": "http://127.0.0.1:59999"}
    secret = "sk-proj-" + "syntheticconfigkey1234567890"
    nik = "3273011508950001"

    leads_csv = tmp_path / "leads.csv"
    leads_csv.write_text(f"id,nik\n1,{nik}\n", encoding="utf-8")

    app_json = tmp_path / "appsettings.json"
    app_json.write_text(json.dumps({"OpenAI": {"ApiKey": secret}}), encoding="utf-8")

    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"name": "demo", "version": "1.0.0"}), encoding="utf-8")

    csv_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "read_file", "args": {"Path": str(leads_csv)}}},
        env_extra=offline_env,
    )
    assert csv_res.returncode == 0
    csv_data = json.loads(csv_res.stdout)
    assert csv_data["decision"] == "deny"
    assert "ID_NIK" in csv_data["reason"]
    assert "run_command" in csv_data["reason"]
    assert nik not in csv_data["reason"]

    json_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "view_file", "args": {"AbsolutePath": str(app_json)}}},
        env_extra=offline_env,
    )
    assert json_res.returncode == 0
    json_data = json.loads(json_res.stdout)
    assert json_data["decision"] == "deny"
    assert "OPENAI_API_KEY" in json_data["reason"]
    assert secret not in json_data["reason"]

    pkg_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "read_file", "args": {"Path": str(pkg_json)}}},
        env_extra=offline_env,
    )
    assert pkg_res.returncode == 0
    assert json.loads(pkg_res.stdout) == {"decision": "allow"}

    envrc_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "view_file_outline", "args": {"AbsolutePath": "C:/app/.envrc"}}},
        env_extra=offline_env,
    )
    assert envrc_res.returncode == 0
    assert json.loads(envrc_res.stdout)["decision"] == "deny"

    aws_res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {"toolCall": {"name": "read_file", "args": {"Path": "C:/Users/me/.aws/credentials"}}},
        env_extra=offline_env,
    )
    assert aws_res.returncode == 0
    assert json.loads(aws_res.stdout)["decision"] == "deny"


def test_antigravity_tool_guard_forwards_conversation_id_to_wrapper() -> None:
    res = _run_guard(
        ANTIGRAVITY_TOOL_GUARD,
        {
            "conversationId": "7997dba8-1569-467f",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "Write-Output 'ok'"}},
        },
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["decision"] == "allow"
    assert "agy-7997dba8-1569-467f" in data["overwrite"]["CommandLine"]


def test_run_command_mask_wrapper_offline_forward_and_deterministic_placeholders() -> None:
    import base64

    k1 = "sk-proj-" + "firstkeydeterministic123456"
    k2 = "sk-proj-" + "secondkeydeterministic12345"
    if os.name == "nt":
        cmd = f"Write-Output 'A={k1}'; Write-Output 'B={k2}'; [Console]::Error.WriteLine('C={k1}')"
    else:
        cmd = f"echo 'A={k1}'; echo 'B={k2}'; echo 'C={k1}' >&2"
    encoded = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    env = {**os.environ, "PII_SHIELD_URL": "http://127.0.0.1:59999"}

    proc = subprocess.run(
        [sys.executable, str(RUN_CMD_WRAPPER), encoded],
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
    )
    assert proc.returncode == 0
    assert k1 not in proc.stdout and k1 not in proc.stderr
    assert k2 not in proc.stdout
    assert "A=<<PII:OPENAI_API_KEY_1>>" in proc.stdout
    assert "B=<<PII:OPENAI_API_KEY_2>>" in proc.stdout
    assert "C=<<PII:OPENAI_API_KEY_1>>" in proc.stderr
