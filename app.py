from __future__ import annotations

import logging
import os
import re
import hmac
import hashlib
import jwt
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from prisma import Prisma

# -------------------------------------------------
# Logging
# -------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("gateway-notion")

# -------------------------------------------------
# Env helpers
# -------------------------------------------------
load_dotenv()

def env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()

JWT_SECRET = env("JWT_SECRET")
JWT_ISSUER = env("JWT_ISSUER", "gateway-notion")
NOTION_URL = env("NOTION_URL")
REDIRECT_HTTP_CODE = int(env("REDIRECT_HTTP_CODE", "302"))

# vazio => aceita todos os eventos (depois você pode restringir via env)
ALLOWED_EVENTS_RAW = env("ALLOWED_EVENTS", "")
ALLOWED_EVENTS = {e.strip() for e in ALLOWED_EVENTS_RAW.split(",") if e.strip()}

WEBHOOK_VERIFY_SECRET = env("WEBHOOK_VERIFY_SECRET")
JWT_EXP_DAYS = int(env("JWT_EXP_DAYS", "365"))
ERR_EXPIRED = env("ERROR_MESSAGE_EXPIRED", "Sua assinatura expirou. Renove para continuar.")
ERR_INVALID = env("ERROR_MESSAGE_INVALID", "Token invalido ou nao encontrado.")

# -------------------------------------------------
# FastAPI + CORS
# -------------------------------------------------
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

# -------------------------------------------------
# Prisma Client
# -------------------------------------------------
db = Prisma()

@app.on_event("startup")
async def on_startup() -> None:
    await db.connect()
    logger.info("Prisma conectado.")

@app.on_event("shutdown")
async def on_shutdown() -> None:
    await db.disconnect()
    logger.info("Prisma desconectado.")

# -------------------------------------------------
# Rotas básicas
# -------------------------------------------------
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs", status_code=302)

@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok"}

# -------------------------------------------------
# Helpers de parsing / JWT
# -------------------------------------------------
def _event_name(payload: dict) -> str:
    return payload.get("event") or payload.get("type") or payload.get("status") or "unknown"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _find_email_anywhere(obj) -> str | None:
    """Busca recursivamente qualquer chave que contenha 'email' e valide formato."""
    if isinstance(obj, dict):
        # muitos webhooks aninham dentro de "data"
        if "data" in obj and isinstance(obj["data"], (dict, list)):
            found = _find_email_anywhere(obj["data"])
            if found:
                return found
        for k, v in obj.items():
            # checa filhos primeiro
            if isinstance(v, (dict, list)):
                found = _find_email_anywhere(v)
                if found:
                    return found
            # checa a própria chave
            if "email" in str(k).lower() and isinstance(v, str) and EMAIL_RE.match(v):
                return v
    elif isinstance(obj, list):
        for item in obj:
            found = _find_email_anywhere(item)
            if found:
                return found
    return None

def _parse_email(payload: dict) -> str | None:
    # tenta campos comuns primeiro
    email = (
        payload.get("email")
        or (payload.get("data") or {}).get("customer_email")
        or (payload.get("customer") or {}).get("email")
        or (payload.get("buyer") or {}).get("email")
        or (payload.get("user") or {}).get("email")
    )
    if isinstance(email, str) and EMAIL_RE.match(email):
        return email
    # fallback: busca recursiva em qualquer lugar
    return _find_email_anywhere(payload)

def _parse_expires(payload: dict):
    # aceita ISO8601 ou timestamp, buscando em chaves comuns
    for k in ("expiresAt", "expires_at", "access_expires_at", "current_period_end"):
        base = payload.get("data") if "data" in payload else payload
        v = (base or {}).get(k)
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except Exception:
                pass
        if isinstance(v, (int, float)):
            try:
                return datetime.fromtimestamp(float(v), tz=timezone.utc)
            except Exception:
                pass
    return None

def _gen_jwt(email: str, status: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,
        "iss": JWT_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=JWT_EXP_DAYS)).timestamp()),
        "status": status,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token.decode("utf-8") if isinstance(token, bytes) else token

# -------------------------------------------------
# Webhook Kiwify
# -------------------------------------------------
@app.post("/webhook/kiwify", tags=["webhook"], summary="Recebe eventos da Kiwify")
async def kiwify_webhook(request: Request):
    # corpo cru e JSON
    raw: bytes = await request.body()
    try:
        body = await request.json()
    except Exception:
        body = {}

    # log de diagnóstico para enxergar o formato real do payload
    try:
        logger.info(f"[webhook] raw-keys={list(body.keys())} body={body}")
    except Exception:
        logger.info("[webhook] body log skipped (non-serializable)")

    # assinatura/token (query ou headers). A Kiwify costuma usar ?signature=
    signature = (
        request.query_params.get("signature")
        or request.headers.get("X-Kiwify-Token")
        or request.headers.get("X-Webhook-Token")
        or request.headers.get("X-Signature")
        or ""
    ).strip().lower()

    # valida token puro OU HMAC-SHA1/SHA256 do corpo
    def _match_hmac(algo: str) -> bool:
        if not (WEBHOOK_VERIFY_SECRET and signature):
            return False
        digest = hmac.new(WEBHOOK_VERIFY_SECRET.encode(), raw, getattr(hashlib, algo)).hexdigest()
        return hmac.compare_digest(signature, digest)

    token_ok = WEBHOOK_VERIFY_SECRET and signature == WEBHOOK_VERIFY_SECRET.lower()
    hmac_ok = _match_hmac("sha1") or _match_hmac("sha256")

    if WEBHOOK_VERIFY_SECRET and not (token_ok or hmac_ok):
        raise HTTPException(status_code=403, detail="invalid signature")

    event = _event_name(body)
    email = _parse_email(body)
    logger.info(f"[webhook] event={event!r} email={email!r}")

    # filtro de eventos: vazio => aceita todos
    if ALLOWED_EVENTS and event not in ALLOWED_EVENTS:
        return JSONResponse({"ok": True, "ignored": True, "event": event}, status_code=202)

    # se o payload de teste não trouxer email, não falhe: responda 200 informativo
    if not email:
        logger.info("[webhook] sem e-mail no payload — retornando 200 (provável webhook de teste)")
        return JSONResponse(
            {"ok": True, "saved": False, "reason": "no email in payload", "event": event},
            status_code=200,
        )

    # status e expiração
    status = (
        "ACTIVE" if any(s in event for s in ("renew", "created", "approved"))
        else "INACTIVE" if "cancel" in event
        else "UNKNOWN"
    )
    exp = _parse_expires(body) or (datetime.now(timezone.utc) + timedelta(days=JWT_EXP_DAYS))

    # gera JWT
    token = _gen_jwt(email, status)

    # upsert na tabela Subscription (colunas: email, jwt, status, expiresAt)
    try:
        await db.subscription.upsert(
            where={"email": email},
            data={
                "create": {"email": email, "jwt": token, "status": status, "expiresAt": exp},
                "update": {"jwt": token, "status": status, "expiresAt": exp},
            },
        )
        logger.info(f"[webhook] upsert ok email={email} status={status}")
    except Exception:
        logger.exception("[webhook] upsert FAILED")
        raise HTTPException(status_code=500, detail="database error")

    return {"ok": True, "event": event, "email": email, "jwt": token}

# -------------------------------------------------
# Validação e redirecionamento
# -------------------------------------------------
@app.get(
    "/a/{token}",
    tags=["auth"],
    summary="Valida token JWT e redireciona para a URL do Notion",
)
async def access(token: str):
    # valida JWT
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer=JWT_ISSUER)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=403, detail=ERR_EXPIRED)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail=ERR_INVALID)

    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=403, detail=ERR_INVALID)

    # checa registro no banco
    try:
        rec = await db.subscription.find_unique(where={"email": email})
    except Exception:
        logger.exception("Erro ao consultar Subscription.")
        raise HTTPException(status_code=500, detail="Erro interno no servidor")

    if not rec or rec.status != "ACTIVE" or getattr(rec, "jwt", None) != token:
        raise HTTPException(status_code=403, detail=ERR_INVALID)

    # redireciona
    if not NOTION_URL:
        raise HTTPException(status_code=500, detail="NOTION_URL não configurada")
    return RedirectResponse(NOTION_URL, status_code=REDIRECT_HTTP_CODE)
