"""Antigravity PreInvocation Safety Gate hook for PII-Shield.

Reads hook JSON payload from stdin. Checks `lastUserInput` against the running
PII-Shield server (/api/v1/scan) with automatic fallback to FastRegexFallbackScanner
if the background server is offline. Never logs or echoes raw secret values.
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
    matches = scanner.scan(text)
    seen: list[str] = []
    for m in matches:
        if m.entity_type not in seen:
            seen.append(m.entity_type)
    return seen


def main() -> int:
    try:
        raw_stdin = sys.stdin.read()
        payload = json.loads(raw_stdin) if raw_stdin.strip() else {}
    except json.JSONDecodeError:
        print(json.dumps({"terminationBehavior": ""}))
        return 0

    text = str(payload.get("lastUserInput") or "")
    if not text.strip():
        print(json.dumps({"terminationBehavior": ""}))
        return 0

    detected_types = _scan_via_server(text)
    mode = "server"
    if detected_types is None:
        detected_types = _scan_offline_fallback(text)
        mode = "offline-fallback"

    if detected_types:
        summary = ", ".join(detected_types)
        output = {
            "terminationBehavior": "terminate",
            "injectSteps": [
                {
                    "errorMessage": {
                        "userMessage": (
                            f"[PII-Shield] Pengiriman ke model diblokir ({mode}). "
                            f"Terdeteksi data sensitif: {summary}. "
                            "Hapus atau samarkan nilai sensitif tersebut sebelum mengirim ulang."
                        )
                    }
                }
            ],
        }
        print(json.dumps(output, ensure_ascii=False))
        return 0

    print(json.dumps({"terminationBehavior": ""}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
