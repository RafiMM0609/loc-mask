# AGENTS.md — Setup & Operations Guide for AI Agents

This repository provides **PII-Shield**, a local Python masking server (`http://127.0.0.1:8787`) and agent connectors for **Antigravity (`agy`)**, **T3 Code**, **Codex CLI**, and **Pi dev CLI**.

## 1. Environment Setup (Fresh Clone)

1. Verify Python `>=3.11,<3.14` is available.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   # Windows: .venv\Scripts\python.exe -m pip install -e .
   # Linux/macOS: .venv/bin/python -m pip install -e .
   ```
3. Download the spaCy English model required by Presidio:
   ```bash
   .venv/Scripts/python.exe -m spacy download en_core_web_sm
   ```
4. `connectors/antigravity/hooks.example.json` uses `~/pii-shield` placeholders; running `connectors/install_connectors.py --apply` automatically resolves the local `.venv` Python and repo paths for Windows, Linux, and macOS.
5. Run the test suite to verify everything passes before applying any connector:
   ```bash
   .venv/Scripts/pytest.exe -v
   ```

## 2. Running & Verifying the Server

- **Start:** `pii-shield.cmd start` (or `.venv/Scripts/python.exe -m pii_shield.cli start --foreground --host 127.0.0.1 --port 8787` inside daemon runners)
- **Status:** `pii-shield.cmd status`
- **Roundtrip Test:** `pii-shield.cmd test "API key sk-proj-test1234567890abcdef123456"`
- **Stop:** `pii-shield.cmd stop`

> **Note:** After editing `config.yaml` or files under `pii_shield/`, restart the server so changes take effect. Connector scripts under `connectors/` are invoked per hook/request and do not require a server restart.

## 3. Installing Connectors Safely

Always inspect status and dry-run first, and only apply connectors the user asks for:

```bash
.venv/Scripts/python.exe connectors/install_connectors.py --status
.venv/Scripts/python.exe connectors/install_connectors.py --apply all --dry-run
```

Targets supported by `install_connectors.py --apply <antigravity|codex|pi|all>`:
- `antigravity`: Installs `PreInvocation` + `PreToolUse` hooks (`run_command|read_file|view_file|view_file_outline|view_code_item|grep_search`) into `~/.gemini/config/hooks.json` and any `~/.t3/userdata/providers/antigravity/*/config/hooks.json` with idempotent `.bak.*` backups, forwarding `agy-<conversationId>` as the masking session ID. Inside Antigravity's Terminal Sandbox, `--status` safely reports `RESTRICTED (permission denied)` for `~/.gemini/config/hooks.json`; run `--apply antigravity` or `--rollback` outside the sandbox (`BypassSandbox: true` or a standard host terminal) when updating `~/.gemini/config/`.
- `codex`: Installs `UserPromptSubmit` for local prompt scanning and `PostToolUse` for shell output masking in `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`). Users can review and trust the hooks in `/hooks` in a new session. The installer migrates legacy PS proxy blocks when it can identify the previous provider. Use `--rollback codex` to restore the pre-install snapshot for Codex alone.
- `pi`: Copies `connectors/pi/pii-shield.ts` to `~/.pi/agent/extensions/pii-shield.ts`.
- Rollback anytime with `--rollback`.

## 4. Guardrails for Agents Working on This Repo

- **Never commit real secrets or `.env` values.** Test fixtures that match provider token prefixes (e.g., Slack/Stripe) must be constructed via string concatenation so GitHub Push Protection does not block pushes.
- **Do not use `read_file`/`view_file`/`view_file_outline`/`view_code_item` or `grep_search` on `.env`, private key files, or config/data/log files containing secrets/PII** when Antigravity `PreToolUse` hooks are active; `antigravity_tool_guard.py` blocks direct unmasked reads and redirects to `run_command` so output is automatically masked.
- **Keep `.venv/`, `.run/`, `__pycache__/`, and `.pytest_cache/` untracked** (handled by `.gitignore`).

## 5. Antigravity & T3 Code ToS Compliance & Architecture Notes

- **Official Hooks Only (No OAuth/API Proxy for Antigravity):** Antigravity (`agy`) and T3 Code integration **must only** use official `hooks.json` lifecycle contracts (`PreInvocation` + `PreToolUse`) alongside the unmodified `agy` / `antigravity-acp` binary. Never route Antigravity personal OAuth traffic through a local HTTP/MITM proxy or pool multiple personal Google accounts concurrently in T3 Code, as that violates Google Antigravity Additional Terms of Service (Section 6).
- **Buffered `run_command` Output:** `run_command_mask_wrapper.py` buffers `stdout`/`stderr` until command exit so multi-line secrets (e.g., PEM private keys) can be reliably scanned and redacted before reaching the model. Long-running background processes with `IsDaemon: true` bypass the wrapper automatically.
