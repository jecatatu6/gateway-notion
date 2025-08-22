from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pydantic.networks import EmailStr
import os, jwt, datetime, logging
from dotenv import load_dotenv
from prisma import Prisma
import hmac, hashlib

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

load_dotenv()
app = FastAPI(
    title="Gateway Notion",
    docs_url="/docs",
    openapi_url="/openapi.json",
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Prisma()

# raiz -> redireciona para /docs (evita 404 na raiz)
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs", status_code=302)

# verificação simples de saúde
@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok"}

# webhook Kiwify (versão mínima só para teste de caminho/assinatura)
@app.post("/webhook/kiwify", tags=["webhook"])
async def kiwify_webhook(request: Request):
    secret_expected = (os.getenv("WEBHOOK_VERIFY_SECRET") or "").strip()

    raw_body: bytes = await request.body()
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    # assinatura enviada pela Kiwify (query ou headers)
    signature = (
        request.query_params.get("signature")
        or request.headers.get("X-Kiwify-Token")
        or request.headers.get("X-Webhook-Token")
        or request.headers.get("X-Signature")
        or ""
    ).strip().lower()

    def match(sig: str, digest: str) -> bool:
        return bool(sig) and hmac.compare_digest(sig, digest)

    # calcule ambas as variantes
    sha1  = hmac.new(secret_expected.encode(), raw_body, hashlib.sha1 ).hexdigest()
    sha256 = hmac.new(secret_expected.encode(), raw_body, hashlib.sha256).hexdigest()

    token_ok = secret_expected and signature == secret_expected.lower()
    hmac_ok = match(signature, sha1) or match(signature, sha256)

    if secret_expected and not (token_ok or hmac_ok):
        raise HTTPException(status_code=403, detail="invalid signature")

    return {"received": True, "verified": "token" if token_ok else ("hmac-sha1" if match(signature, sha1) else "hmac-sha256"), "event": payload.get("event")}

# Modelos e rostas mantêm-se exatamente como estavam

@app.on_event("startup")
async def startup():
    await db.connect()

@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()
