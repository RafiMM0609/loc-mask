"""Block Codex prompts that contain sensitive text before inference."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

def _scan_via_server(text: str, port: int) -> list[str] | None:
    url = os.environ.get("PII_SHIELD_URL") or f"http://127.0.0.1:{port}"
    try:
        endpoint = urllib.parse.urlsplit(url)
        if endpoint.scheme not in {"http", "https"} or endpoint.hostname not in {"127.0.0.1", "::1", "localhost"}:
            return None
        request = urllib.request.Request(
            f"{url.rstrip('/')}/api/v1/scan",
            data=json.dumps({"text": text}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=0.6) as response:
            result = json.load(response)
        sensitive = result["has_sensitive"]
        types = result["entity_types"]
        if type(sensitive) is bool and isinstance(types, list) and sensitive == bool(types):
            if all(isinstance(item, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", item) for item in types):
                return types
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def _block(reason: str) -> None:
    print(json.dumps({"decision": "block", "reason": f"[PII-Shield] {reason}"}))


def _scan_offline(text: str, cfg) -> list[str]:
    from pii_shield.patterns import FastRegexFallbackScanner

    scanner = FastRegexFallbackScanner(
        detect_secrets=cfg.masking.detect_secrets,
        detect_pii=cfg.masking.detect_pii,
        allowlist_values=cfg.allowlist_values,
    )
    return list(dict.fromkeys(match.entity_type for match in scanner.scan(text)))


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        prompt = payload.get("prompt", payload.get("user_prompt"))
        if not isinstance(prompt, str):
            raise ValueError("Invalid prompt")
        if not prompt.strip():
            return

        from pii_shield.config import load_config

        cfg = load_config()
        detected = _scan_via_server(prompt, cfg.server.port)
        if detected is None:
            detected = _scan_offline(prompt, cfg)
    except Exception:
        _block("Prompt diblokir karena scanner tidak tersedia.")
        return

    if detected:
        _block(f"Prompt diblokir. Samarkan data berikut sebelum kirim ulang ({', '.join(detected)}).")


if __name__ == "__main__":
    main()
