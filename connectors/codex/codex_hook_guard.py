"""Optional Codex CLI UserPromptSubmit hook guard for PII-Shield.

If you prefer block-only safety gate instead of (or in addition to) the reverse proxy,
this hook exits with code 2 and prints a reason to stderr when sensitive data is detected.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

PII_SHIELD_URL = os.environ.get("PII_SHIELD_URL", "http://127.0.0.1:8787").rstrip("/")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


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

    text = str(payload.get("prompt") or payload.get("user_prompt") or "")
    if not text.strip():
        return 0

    detected = _scan_via_server(text)
    if detected is None:
        detected = _scan_offline_fallback(text)

    if detected:
        print(
            f"[PII-Shield] Prompt diblokir! Terdeteksi data sensitif: {', '.join(detected)}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
