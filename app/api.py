"""HTTP API and web UI.

GET  /health, /tactics, /scenarios, /scenarios/{id}, /coverage  read-only, no LLM
POST /tools                                                     direct tool call, no LLM
POST /ask                                                       LLM tool loop (rate-limited per IP)
GET  /                                                          single-page UI (web/index.html)

Run with: uvicorn app.api:app --reload
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import agent as agent_module
from .attack import load_attack
from .config import Settings, configure_logging, get_settings
from .library import load_library, select, to_yaml
from .ratelimit import RateLimiter
from .scenarios import coverage, validate_scenario
from .tools import ToolContext, run_tool, scenario_summary
from .ui import ui_payload

logger = logging.getLogger(__name__)
INDEX_HTML = Path(__file__).resolve().parent.parent / "web" / "index.html"
RATE_WINDOW_S = 3600


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class ToolRequest(BaseModel):
    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)


def client_ip(request: Request, trust_forwarded_for: bool) -> str:
    """Address used as rate-limit key.

    Behind a reverse proxy (Render) every request comes from the proxy, so the
    first X-Forwarded-For entry is used when TRUST_FORWARDED_FOR is set. Only
    enable it behind a proxy you trust: clients can forge the header otherwise.
    """
    if trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.client.host if request.client else "unknown"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    attack = load_attack()
    library = load_library()
    limiter = RateLimiter(settings.rate_limit_per_hour, RATE_WINDOW_S)

    app = FastAPI(
        title="Cyber Range Scenario Assistant",
        version="0.1.0",
        description="Plan, validate, aggregate and gap-analyse ATT&CK-mapped cyber range training scenarios.",
    )

    def new_context() -> ToolContext:
        # The library is read-only: tools only add to the per-request session.
        return ToolContext(attack, list(library))

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(INDEX_HTML, media_type="text/html")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "attack_version": attack.version,
            "techniques": len(attack.techniques),
            "scenarios": len(library),
            "llm_configured": settings.llm_configured,
            "llm_model": settings.llm_model,
        }

    @app.get("/tactics")
    def tactics() -> list[dict[str, str]]:
        return attack.tactics

    @app.get("/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return [scenario_summary(s) for s in library]

    @app.get("/scenarios/{scenario_id}")
    def scenario(scenario_id: str) -> dict[str, Any]:
        try:
            scn = select(library, [scenario_id.upper()])[0]
        except KeyError:
            raise HTTPException(404, f"unknown scenario {scenario_id}") from None
        return {"scenario": scn, "yaml": to_yaml(scn), "validation": validate_scenario(attack, scn)}

    @app.get("/coverage")
    def get_coverage() -> dict[str, Any]:
        return coverage(attack, library)

    @app.post("/tools")
    def tools(req: ToolRequest) -> JSONResponse:
        ctx = new_context()
        result = run_tool(ctx, req.tool, req.args)
        if "error" in result:
            return JSONResponse({"error": result["error"]}, status_code=400)
        return JSONResponse({"tool": req.tool, "result": result, "ui": ui_payload(ctx, [(req.tool, result)])})

    @app.post("/ask")
    def ask(req: AskRequest, request: Request) -> JSONResponse:
        if settings.rate_limit_per_hour:
            ip = client_ip(request, settings.trust_forwarded_for)
            wait = limiter.retry_after(ip)
            if wait > 0:
                minutes = max(1, math.ceil(wait / 60))
                logger.info("rate limit reached for %s", ip)
                return JSONResponse(
                    {
                        "error": f"Limit of {settings.rate_limit_per_hour} questions per hour reached; "
                        f"try again in {minutes} min. The Coverage and Gap analysis buttons still work."
                    },
                    status_code=429,
                    headers={"Retry-After": str(math.ceil(wait))},
                )
            limiter.hit(ip)
        if not settings.llm_configured:
            return JSONResponse(
                {"error": "No LLM is configured (LLM_API_KEY). Direct tools still work."}, status_code=503
            )
        try:
            result = agent_module.run_agent(req.question, new_context(), settings)
        except agent_module.LLMError as exc:
            logger.warning("LLM failure: %s", exc)
            return JSONResponse(
                {"error": "The language model is unreachable right now. Direct tools still work."},
                status_code=502,
            )
        return JSONResponse(result)

    return app


app = create_app()
