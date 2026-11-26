"""Reverse proxy router with automatic 2-way masking and SSE streaming unmasking."""

from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from pii_shield.engine import MaskingEngine
from pii_shield.vault import StreamingUnmaskBuffer

logger = logging.getLogger("pii_shield.proxy")

router = APIRouter()

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "upgrade",
    "accept-encoding",
}


def _filter_request_headers(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in HOP_BY_HOP_HEADERS:
            continue
        out[k] = v
    return out


def _filter_response_headers(headers: httpx.Headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        low = k.lower()
        if low in HOP_BY_HOP_HEADERS or low == "content-encoding":
            continue
        out[k] = v
    return out


def _extract_session_id(request: Request) -> str:
    return (
        request.headers.get("x-pii-session")
        or request.headers.get("session_id")
        or request.headers.get("x-codex-thread-id")
        or request.headers.get("x-session-id")
        or request.headers.get("chatgpt-account-id")
        or "default"
    )


def _unmask_sse_event_obj(
    event_obj: dict[str, Any],
    engine: MaskingEngine,
    session_id: str,
    buffers: dict[str, StreamingUnmaskBuffer],
) -> dict[str, Any]:
    """Unmask streaming deltas and completed items across Chat Completions and Responses API."""

    def _buf(key: str) -> StreamingUnmaskBuffer:
        if key not in buffers:
            buffers[key] = StreamingUnmaskBuffer(engine.vault, session_id=session_id)
        return buffers[key]

    # 1. OpenAI Chat Completions streaming chunks
    choices = event_obj.get("choices")
    if isinstance(choices, list):
        for idx, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if isinstance(delta, dict):
                if isinstance(delta.get("content"), str):
                    delta["content"] = _buf(f"chat_{idx}_content").feed(delta["content"])
                if isinstance(delta.get("reasoning_content"), str):
                    delta["reasoning_content"] = _buf(f"chat_{idx}_reasoning").feed(
                        delta["reasoning_content"]
                    )
                tool_calls = delta.get("tool_calls")
                if isinstance(tool_calls, list):
                    for tc_idx, tc in enumerate(tool_calls):
                        if isinstance(tc, dict) and isinstance(tc.get("function"), dict):
                            fn = tc["function"]
                            if isinstance(fn.get("arguments"), str):
                                fn["arguments"] = _buf(f"chat_{idx}_tc_{tc_idx}").feed(
                                    fn["arguments"]
                                )
            msg = choice.get("message")
            if isinstance(msg, dict):
                choice["message"], _ = engine.unmask_payload(msg, session_id=session_id)

    # 2. OpenAI Responses / Codex SSE events
    ev_type = event_obj.get("type")
    if ev_type == "response.output_text.delta" and isinstance(event_obj.get("delta"), str):
        item_key = str(event_obj.get("item_id") or "output_text")
        event_obj["delta"] = _buf(f"resp_text_{item_key}").feed(event_obj["delta"])
    elif ev_type == "response.function_call_arguments.delta" and isinstance(
        event_obj.get("delta"), str
    ):
        item_key = str(event_obj.get("item_id") or "fn_args")
        event_obj["delta"] = _buf(f"resp_fn_{item_key}").feed(event_obj["delta"])
    elif ev_type == "response.reasoning_summary_text.delta" and isinstance(
        event_obj.get("delta"), str
    ):
        item_key = str(event_obj.get("item_id") or "reasoning")
        event_obj["delta"] = _buf(f"resp_reason_{item_key}").feed(event_obj["delta"])
    elif ev_type in {
        "response.output_text.done",
        "response.function_call_arguments.done",
        "response.content_part.done",
        "response.output_item.done",
        "response.completed",
    }:
        # Flush buffered tail if any, and unmask full payload fields.
        for buf in buffers.values():
            buf.flush()
        event_obj, _ = engine.unmask_payload(event_obj, session_id=session_id)

    return event_obj


async def _forward_request(request: Request, target_url: str) -> Response:
    engine: MaskingEngine = request.app.state.engine
    client: httpx.AsyncClient = request.app.state.proxy_client
    session_id = _extract_session_id(request)

    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    raw_body = await request.body()
    content_type = request.headers.get("content-type", "")
    headers = _filter_request_headers(request.headers)

    # The installed provider sends plain JSON over HTTP/SSE. Never pass a body
    # we cannot inspect through to the model (e.g. a compressed legacy request).
    if raw_body and request.headers.get("content-encoding", "identity").lower() != "identity":
        return JSONResponse(status_code=415, content={"error": "unsupported_content_encoding"})
    if raw_body and "application/json" not in content_type.lower():
        return JSONResponse(status_code=415, content={"error": "expected_json_payload"})
    if raw_body:
        try:
            payload = json.loads(raw_body.decode("utf-8"))
            masked_payload, masked_types = engine.mask_payload(payload, session_id=session_id)
            if masked_types:
                logger.info(
                    "Masked outgoing payload for %s (session=%s, types=%s)",
                    request.url.path,
                    session_id,
                    ",".join(masked_types),
                )
            raw_body = json.dumps(masked_payload, ensure_ascii=False).encode("utf-8")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return JSONResponse(status_code=400, content={"error": "invalid_json_payload"})
        except Exception:
            logger.error("Outgoing masking failed; request was not forwarded")
            return JSONResponse(status_code=503, content={"error": "masking_unavailable"})

    upstream_req = client.build_request(
        method=request.method,
        url=target_url,
        headers=headers,
        content=raw_body,
    )

    try:
        upstream_resp = await client.send(upstream_req, stream=True)
    except httpx.RequestError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": "upstream_connection_error", "detail": str(exc)},
        )

    resp_headers = _filter_response_headers(upstream_resp.headers)
    resp_ct = upstream_resp.headers.get("content-type", "").lower()

    if "text/event-stream" in resp_ct:
        buffers: dict[str, StreamingUnmaskBuffer] = {}

        async def _sse_stream() -> AsyncIterator[bytes]:
            try:
                async for line in upstream_resp.aiter_lines():
                    if line.startswith("data: "):
                        raw_data = line[6:]
                        if raw_data.strip() == "[DONE]":
                            yield b"data: [DONE]\n"
                            continue
                        try:
                            event_obj = json.loads(raw_data)
                            if isinstance(event_obj, dict):
                                event_obj = _unmask_sse_event_obj(
                                    event_obj, engine, session_id, buffers
                                )
                                encoded = json.dumps(event_obj, ensure_ascii=False)
                                yield f"data: {encoded}\n".encode("utf-8")
                            else:
                                unmasked_str, _ = engine.unmask_text(
                                    raw_data, session_id=session_id
                                )
                                yield f"data: {unmasked_str}\n".encode("utf-8")
                        except json.JSONDecodeError:
                            unmasked_str = buffers.setdefault(
                                "raw", StreamingUnmaskBuffer(engine.vault, session_id=session_id)
                            ).feed(raw_data)
                            yield f"data: {unmasked_str}\n".encode("utf-8")
                    else:
                        yield f"{line}\n".encode("utf-8")
            finally:
                await upstream_resp.aclose()

        return StreamingResponse(
            _sse_stream(),
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type="text/event-stream",
        )

    try:
        resp_body = await upstream_resp.aread()
    finally:
        await upstream_resp.aclose()

    if "application/json" in resp_ct and resp_body:
        try:
            resp_json = json.loads(resp_body.decode("utf-8"))
            unmasked_json, _ = engine.unmask_payload(resp_json, session_id=session_id)
            resp_body = json.dumps(unmasked_json, ensure_ascii=False).encode("utf-8")
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

    return Response(
        content=resp_body,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
    )


@router.api_route(
    "/openai/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_openai(request: Request, path: str) -> Response:
    return await _forward_request(request, f"https://api.openai.com/{path}")


@router.api_route(
    "/chatgpt-backend/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_chatgpt_backend(request: Request, path: str) -> Response:
    if path.startswith("api/"):
        return await _forward_request(request, f"https://chatgpt.com/{path}")
    return await _forward_request(request, f"https://chatgpt.com/backend-api/{path}")


@router.api_route(
    "/proxy/{scheme}/{host}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_generic(request: Request, scheme: str, host: str, path: str) -> Response:
    if scheme.lower() not in {"http", "https"}:
        return JSONResponse(status_code=400, content={"error": "invalid_scheme"})
    return await _forward_request(request, f"{scheme.lower()}://{host}/{path}")
