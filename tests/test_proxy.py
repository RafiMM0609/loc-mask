"""Tests for FastAPI endpoints, SSE streaming unmask buffer, and reverse proxy."""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from pii_shield.config import load_config
from pii_shield.engine import MaskingEngine
from pii_shield.server import create_app
from pii_shield.vault import StreamingUnmaskBuffer


def test_streaming_unmask_buffer_handles_split_placeholder() -> None:
    engine = MaskingEngine(load_config())
    secret = "sk-proj-streamtest1234567890abcdef"
    masked = engine.mask_text(f"key={secret}", session_id="s-stream")
    placeholder = masked.text.split("key=", 1)[1]

    # Split placeholder across 5 arbitrary token fragments
    parts = [
        "Your key is ",
        placeholder[:3],
        placeholder[3:9],
        placeholder[9:15],
        placeholder[15:],
        " ready.",
    ]
    buf = StreamingUnmaskBuffer(engine.vault, session_id="s-stream")
    out = "".join(buf.feed(p) for p in parts) + buf.flush()
    assert out == f"Your key is {secret} ready."


def test_api_endpoints_scan_mask_unmask_and_health() -> None:
    app = create_app(config=load_config())
    with TestClient(app) as client:
        r_health = client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ok"

        secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        r_scan = client.post("/api/v1/scan", json={"text": f"token {secret}"})
        assert r_scan.status_code == 200
        assert r_scan.json()["has_sensitive"] is True
        assert "GITHUB_TOKEN" in r_scan.json()["entity_types"]

        r_mask = client.post(
            "/api/v1/mask",
            json={"text": f"token {secret}", "session_id": "api-1"},
        )
        assert r_mask.status_code == 200
        masked_text = r_mask.json()["text"]
        assert secret not in masked_text

        r_unmask = client.post(
            "/api/v1/unmask",
            json={"text": masked_text, "session_id": "api-1"},
        )
        assert r_unmask.status_code == 200
        assert r_unmask.json()["text"] == f"token {secret}"
        assert r_unmask.json()["restored_count"] == 1


def test_reverse_proxy_masks_request_and_unmasks_sse_stream() -> None:
    seen_upstream_bodies: list[dict] = []
    secret = "sk-proj-proxyintegration1234567890"

    def _mock_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        seen_upstream_bodies.append(body)
        # Upstream only sees placeholder, echoes it back split across 2 SSE deltas!
        sent_text = body["input"][0]["content"]
        placeholder = sent_text.split("Use ")[1]
        sse_lines = [
            f'data: {json.dumps({"type": "response.output_text.delta", "item_id": "msg_1", "delta": "Confirmed: " + placeholder[:8]})}\n\n',
            f'data: {json.dumps({"type": "response.output_text.delta", "item_id": "msg_1", "delta": placeholder[8:] + "!"})}\n\n',
            "data: [DONE]\n\n",
        ]
        return httpx.Response(
            status_code=200,
            headers={"content-type": "text/event-stream"},
            content="".join(sse_lines).encode("utf-8"),
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(_mock_handler))
    app = create_app(config=load_config(), proxy_client=mock_client)

    with TestClient(app) as client:
        resp = client.post(
            "/chatgpt-backend/codex/responses",
            headers={"Authorization": "Bearer user-oauth-token"},
            json={
                "model": "gpt-6.1-sol",
                "input": [{"role": "user", "content": f"Use {secret}"}],
            },
        )
        assert resp.status_code == 200
        assert len(seen_upstream_bodies) == 1
        assert secret not in json.dumps(seen_upstream_bodies[0])
        assert "<<PII:OPENAI_API_KEY_" in seen_upstream_bodies[0]["input"][0]["content"]

        # Reconstruct streamed deltas received by client
        deltas: list[str] = []
        for line in resp.text.splitlines():
            if line.startswith("data: ") and line[6:].strip() != "[DONE]":
                ev = json.loads(line[6:])
                deltas.append(ev["delta"])
        assert "".join(deltas) == f"Confirmed: {secret}!"
