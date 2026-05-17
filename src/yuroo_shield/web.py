"""FastAPI app — wraps AgentOrchestrator behind a /api/scan endpoint and serves
the static single-page UI from web/static/.
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import CHAIN_IDS, load_settings
from .orchestrator import AgentOrchestrator

_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "web" / "static"


class ScanRequest(BaseModel):
    address: str = Field(..., description="Contract address (0x...)")
    chain: str = Field("ethereum", description=f"One of: {', '.join(CHAIN_IDS)}")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Yuroo Shield",
        description="Multi-agent smart contract security scanner — Powered by MiMo.",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    async def health() -> dict:
        s = load_settings()
        return {
            "status": "ok",
            "etherscan_configured": bool(s.etherscan_api_key),
            "llm_configured": s.llm_enabled,
            "llm_provider": s.llm_base_url,
            "llm_model": s.llm_model,
            "chains": list(CHAIN_IDS),
        }

    @app.post("/api/scan")
    async def scan(req: ScanRequest) -> JSONResponse:
        if not _ADDR_RE.match(req.address):
            raise HTTPException(
                status_code=400,
                detail="address must be a 0x-prefixed 40-hex string",
            )
        if req.chain.lower() not in CHAIN_IDS:
            raise HTTPException(
                status_code=400,
                detail=f"unsupported chain. supported: {list(CHAIN_IDS)}",
            )
        try:
            async with AgentOrchestrator() as orch:
                report = await orch.scan_contract(req.address, req.chain.lower())
        except ValueError as e:
            raise HTTPException(status_code=500, detail=str(e)) from e
        return JSONResponse(report.to_dict())

    # Static assets (CSS/JS bundle, banner, favicon)
    if _STATIC_DIR.exists():
        app.mount(
            "/assets",
            StaticFiles(directory=str(_STATIC_DIR / "assets")),
            name="assets",
        )

        @app.get("/")
        async def index() -> FileResponse:
            return FileResponse(_STATIC_DIR / "index.html")

    return app


# uvicorn entrypoint: `uvicorn yuroo_shield.web:app --reload`
app = create_app()
