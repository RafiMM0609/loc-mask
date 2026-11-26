"""FastAPI application for PII-Shield masking API and reverse proxy."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from pii_shield import __version__
from pii_shield.config import AppConfig, load_config
from pii_shield.engine import MaskingEngine
from pii_shield.proxy import router as proxy_router


class ScanRequest(BaseModel):
    text: str = ""


class DetectedEntityOut(BaseModel):
    type: str
    start: int
    end: int
    score: float


class ScanResponse(BaseModel):
    has_sensitive: bool
    count: int
    entity_types: list[str]
    entities: list[DetectedEntityOut]


class MaskRequest(BaseModel):
    text: str | None = None
    payload: Any | None = None
    session_id: str = Field(default="default", min_length=1)


class MaskResponse(BaseModel):
    text: str | None = None
    payload: Any | None = None
    count: int
    entity_types: list[str]


class UnmaskRequest(BaseModel):
    text: str | None = None
    payload: Any | None = None
    session_id: str | None = None


class UnmaskResponse(BaseModel):
    text: str | None = None
    payload: Any | None = None
    restored_count: int


class ClearVaultRequest(BaseModel):
    session_id: str | None = None


def create_app(
    config: AppConfig | None = None,
    engine: MaskingEngine | None = None,
    proxy_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    cfg = config or load_config()
    eng = engine or MaskingEngine(config=cfg)
    owns_client = proxy_client is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.proxy_client is None:
            app.state.proxy_client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=15.0, read=300.0, write=30.0, pool=15.0),
                follow_redirects=True,
            )
        try:
            yield
        finally:
            if owns_client and app.state.proxy_client is not None:
                await app.state.proxy_client.aclose()
                app.state.proxy_client = None

    app = FastAPI(
        title="PII-Shield",
        version=__version__,
        description="Local AI masking server and privacy reverse proxy",
        lifespan=lifespan,
    )
    app.state.config = cfg
    app.state.engine = eng
    app.state.proxy_client = proxy_client

    @app.get("/health")
    async def health(request: Request) -> dict[str, Any]:
        vault_stats = request.app.state.engine.vault.stats()
        return {
            "status": "ok",
            "service": "pii-shield",
            "version": __version__,
            "host": request.app.state.config.server.host,
            "port": request.app.state.config.server.port,
            **vault_stats,
        }

    @app.post("/api/v1/scan", response_model=ScanResponse)
    async def scan_endpoint(body: ScanRequest, request: Request) -> ScanResponse:
        entities = request.app.state.engine.scan_text(body.text)
        types: list[str] = []
        for e in entities:
            if e.entity_type not in types:
                types.append(e.entity_type)
        return ScanResponse(
            has_sensitive=len(entities) > 0,
            count=len(entities),
            entity_types=types,
            entities=[
                DetectedEntityOut(type=e.entity_type, start=e.start, end=e.end, score=e.score)
                for e in entities
            ],
        )

    @app.post("/api/v1/mask", response_model=MaskResponse)
    async def mask_endpoint(body: MaskRequest, request: Request) -> MaskResponse:
        eng_inst: MaskingEngine = request.app.state.engine
        if body.text is None and body.payload is None:
            raise HTTPException(status_code=400, detail="Provide either 'text' or 'payload'.")

        masked_text = None
        masked_payload = None
        total_count = 0
        types: list[str] = []

        if body.text is not None:
            res = eng_inst.mask_text(body.text, session_id=body.session_id)
            masked_text = res.text
            total_count += res.count
            types.extend(res.entity_types)

        if body.payload is not None:
            masked_payload, p_types = eng_inst.mask_payload(
                body.payload, session_id=body.session_id
            )
            for t in p_types:
                if t not in types:
                    types.append(t)
            if body.text is None:
                total_count = len(p_types)

        return MaskResponse(
            text=masked_text,
            payload=masked_payload,
            count=total_count,
            entity_types=types,
        )

    @app.post("/api/v1/unmask", response_model=UnmaskResponse)
    async def unmask_endpoint(body: UnmaskRequest, request: Request) -> UnmaskResponse:
        eng_inst: MaskingEngine = request.app.state.engine
        if body.text is None and body.payload is None:
            raise HTTPException(status_code=400, detail="Provide either 'text' or 'payload'.")

        out_text = None
        out_payload = None
        restored = 0

        if body.text is not None:
            out_text, count = eng_inst.unmask_text(body.text, session_id=body.session_id)
            restored += count

        if body.payload is not None:
            out_payload, count = eng_inst.unmask_payload(
                body.payload, session_id=body.session_id
            )
            restored += count

        return UnmaskResponse(
            text=out_text,
            payload=out_payload,
            restored_count=restored,
        )

    @app.post("/api/v1/vault/clear")
    async def clear_vault_endpoint(body: ClearVaultRequest, request: Request) -> dict[str, int]:
        removed = request.app.state.engine.vault.clear(session_id=body.session_id)
        return {"removed": removed}

    app.include_router(proxy_router)
    return app


app = create_app()
