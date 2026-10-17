"""FastAPI gateway. Run with: uvicorn api:create_app --factory"""
import hashlib, hmac, os, time
from collections import defaultdict, deque
from pathlib import Path
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from audit import Audit
from connector import MockAIConnector
from detector import nlp_available
from gateway import Gateway
from policy import load_config

STATIC = Path(__file__).parent / "static"
MAX_BODY = 64 * 1024
ROLE_CAN = {"user": {"inspect"}, "analyst": {"inspect", "read"}, "admin": {"inspect", "read"}}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

def _h(v: str) -> bytes:
    return hashlib.sha256(v.encode()).digest()

def parse_keys(raw: str) -> dict[bytes, tuple[str, str]]:
    """DATAVAULT_KEYS='name:role:key,...' -> {sha256(key): (name, role)}. Raw keys are not kept."""
    out = {}
    for item in filter(None, (raw or "").split(",")):
        name, role, key = item.strip().split(":", 2)
        if role not in ROLE_CAN or len(key) < 24:
            raise ValueError("invalid key entry: role must be user/analyst/admin and key >= 24 chars")
        out[_h(key)] = (name, role)
    if not out:
        raise RuntimeError("No API keys configured. Run: python scripts/gen_keys.py")
    return out

class Limiter:
    def __init__(self, limit, window=60):
        self.limit, self.window, self.hits = limit, window, defaultdict(deque)
    def allow(self, k):
        now, q = time.monotonic(), self.hits[k]
        while q and now - q[0] > self.window: q.popleft()
        if len(q) >= self.limit: return False
        q.append(now); return True

class InspectIn(BaseModel):
    text: str = Field(min_length=1, max_length=20000)
    destination: str = Field(default="approved_ai", pattern=r"^[a-z0-9_]{1,40}$")

def create_app(keys_raw=None, audit_path=None, cfg=None, connector=None) -> FastAPI:
    keys = parse_keys(keys_raw if keys_raw is not None else os.environ.get("DATAVAULT_KEYS", ""))
    cfg = cfg or load_config()
    connector = connector or MockAIConnector()
    audit = Audit(audit_path or os.environ.get("DATAVAULT_DB", "datavault_audit.db"))
    gw = Gateway(cfg, audit, connector)
    app = FastAPI(title="DataVault AI", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.connector, app.state.audit = connector, audit
    ok_limit, bad_limit = Limiter(60), Limiter(10)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        resp = await call_next(request)
        resp.headers.update({"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                             "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                             "Cache-Control": "no-store", "Strict-Transport-Security": "max-age=31536000"})
        return resp

    @app.exception_handler(Exception)
    async def _err(request, exc):   # never leak internals or request content
        return JSONResponse({"detail": "internal error"}, status_code=500)

    def auth(need):
        def dep(request: Request, x_api_key: str = Header(default="")):
            ip = request.client.host if request.client else "?"
            digest = _h(x_api_key)
            entry = None
            for k, v in keys.items():            # constant-time compare against every key
                if hmac.compare_digest(k, digest): entry = v
            if entry is None:
                if not bad_limit.allow(ip):
                    raise HTTPException(429, "too many failed attempts")
                raise HTTPException(401, "invalid or missing API key")
            name, role = entry
            if need not in ROLE_CAN[role]:
                raise HTTPException(403, "role not permitted")
            if not ok_limit.allow(name):
                raise HTTPException(429, "rate limit exceeded")
            return name, role
        return dep

    @app.get("/healthz")
    def health():
        return {"status": "ok", "nlp_engine": "presidio" if nlp_available() else "rules-only"}

    @app.post("/v1/inspect")
    def inspect(body: InspectIn, who=Depends(auth("inspect"))):
        return gw.process(body.text, who[0], who[1], body.destination)

    @app.get("/v1/events")
    def events(limit: int = 50, who=Depends(auth("read"))):
        return audit.recent(max(1, min(limit, 200)))

    @app.get("/v1/metrics")
    def metrics(who=Depends(auth("read"))):
        return audit.metrics()

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
