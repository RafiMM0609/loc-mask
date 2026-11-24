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
4. Update the absolute Python and script paths in `connectors/antigravity/hooks.example.json` to match the local clone directory if the repo is not at `~/pii-shield`.
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
- `antigravity`: Installs `PreInvocation` + `PreToolUse` hooks into `~/.gemini/config/hooks.json` and any `~/.t3/userdata/providers/antigravity/*/config/hooks.json`.
- `codex`: Prepends `chatgpt_base_url = "http://127.0.0.1:8787/chatgpt-backend/"` to `~/.codex/config.toml` (with `.bak` backup).
- `pi`: Copies `connectors/pi/pii-shield.ts` to `~/.pi/agent/extensions/pii-shield.ts`.
- Rollback anytime with `--rollback`.

## 4. Guardrails for Agents Working on This Repo

- **Never commit real secrets or `.env` values.** Test fixtures that match provider token prefixes (e.g., Slack/Stripe) must be constructed via string concatenation so GitHub Push Protection does not block pushes.
- **Do not use `read_file`/`view_file` on `.env` or private key files** when Antigravity `PreToolUse` hooks are active; use `run_command` so output is automatically masked.
- **Keep `.venv/`, `.run/`, `__pycache__/`, and `.pytest_cache/` untracked** (handled by `.gitignore`).
