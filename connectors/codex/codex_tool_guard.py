"""Codex CLI PreToolUse hook guard for PII-Shield.

Protects against leaking secrets/PII via Bash tool calls:
- Blocks commands that directly reference sensitive files (.env, private keys, credentials).
- Blocks commands whose text contains raw secrets or PII (via live PII-Shield server or offline regex fallback).
- Exits 0 for normal commands so Codex's built-in sandbox and approval policies remain intact.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

PII_SHIELD_URL = os.environ.get("PII_SHIELD_URL", "http://127.0.0.1:8787").rstrip("/")
PROJECT_ROOT = Path(__file__).resolve().parents[2]

SENSITIVE_CMD_RE = re.compile(
    r"(?:^|[\s'\"/\\(=,;])("
    r"\.env(?!\.(?:example|sample|template)(?![A-Za-z0-9_.-]))(?:\.[A-Za-z0-9_.-]+)?"
    r"|id_rsa|id_ed25519|id_ecdsa"
    r"|credentials\.json|secrets\.ya?ml|\.npmrc|\.pypirc|\.netrc"
    r"|service-account[^/\s'\"]*\.json"
    r"|[A-Za-z0-9_.-]+\.(?:pem|key|p12|pfx)"
    r")(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)


def _scan_via_server(text: str) -> list[str] | None:
    req = urllib.request.Request(
        f"{PII_SHIELD_URL}/api/v1/scan",
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=0.6) as resp:
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
    for m in scanner.scan(text):
        if m.entity_type not in seen:
            seen.append(m.entity_type)
    return seen


def main() -> int:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0

    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return 0

    command = str(tool_input.get("command") or "")
    if not command.strip():
        return 0

    sensitive_match = SENSITIVE_CMD_RE.search(command)
    if sensitive_match:
        target = sensitive_match.group(1)
        print(
            f"[PII-Shield] Perintah diblokir! Terdeteksi akses file sensitif '{target}' "
            "yang berisiko membocorkan kredensial ke konteks model.",
            file=sys.stderr,
        )
        return 2

    detected = _scan_via_server(command)
    if detected is None:
        detected = _scan_offline_fallback(command)

    if detected:
        print(
            f"[PII-Shield] Perintah diblokir! Terdeteksi data sensitif pada argumen perintah: {', '.join(detected)}",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
