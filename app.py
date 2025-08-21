# app.py
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pydantic.networks import EmailStr
import os, jwt, datetime, logging
from dotenv import load_dotenv
import subprocess, sys, pathlib

# ---------------------- LOGGING ----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------- ENV -------------------------
load_dotenv()

# ----------------- PRISMA: SAFE GENERATE -------------
def _ensure_prisma_client():
    """
    Garante que o prisma-client-py foi gerado antes de importar Prisma.
    Útil no Render quando o preDeploy não rodou ou rodou fora de ordem.
    """
    try:
        from prisma import Prisma  # noqa: F401
        logger.info("Prisma client já disponível.")
        return
    except RuntimeError as e:
        logger.warning(f"Prisma client não encontrado. Gerando... ({e})")
        schema = "prisma/schema.prisma"
        if not pathlib.Path(schema).exists():
            raise RuntimeError(f"Arquivo {schema} não encontrado para gerar prisma client.")
        # Executa: python -m prisma generate --schema=prisma/schema.prisma
        subprocess.run(
            [sys.executable, "-m", "prisma", "generate", "--schema", schema],
            check=True,
        )
        from prisma import Prisma  # noqa: F401
        logger.info("Prisma client gerado com sucesso.")

_ensure_prisma_client()
from prisma import Prisma  # agora é seguro importar

# ---------------------- FASTAPI ----------------------
app = FastAPI()

# CORS liberado (útil para testes via Swagger)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------- DB CLIENT --------------------
db = Prisma()

# ---------------------- MODELOS ----------------------
class KiwifyData(BaseModel):
    customer_email: EmailStr

class KiwifyWebhook(BaseModel):
    event: str
    data: KiwifyData

# ------------------ CONFIGURAÇÕES --------------------
try:
    SECRET = os.environ["JWT_SECRET"]
    ISSUER = os.environ["JWT_ISSUER"]
    NOTION_URL = os.environ["NOTION_URL"]
except KeyError as e:
    missing = str(e).strip("'")
    raise RuntimeError(f"Variável de ambiente obrigatória ausente: {missing}")

REDIRECT_CODE = int(os.environ.get("REDIRECT_HTTP_CODE", "302"))
ALLOWED_EVENTS = set(os.environ.get(
    "ALLOWED_EVENTS",
    "subscription.created,subscription.renewed,subscription.canceled"
).split(","))
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_VERIFY_SECRET")
EXP_DAYS = int(os.environ.get("JWT_EXP_DAYS", "365"))

# ----------------- LIFECYCLE HOOKS -------------------
@app.on_event("startup")
async def startup():
    logger.info("Conectando ao banco via Prisma...")
    await db.connect()
    logger.info("Conectado.")

@app.on_event("shutdown")
async def shutdown():
    logger.info("Desconectando do banco...")
    await db.disconnect()
    logger.info("Desconectado.")

# ------------------ FUNÇÕES AUX ----------------------
def gen_jwt(email: str, days: int) -> str:
    exp = datetime.datetime.utcnow() + datetime.timedelta(days=days)
    token = jwt.encode({"sub": email, "iss": ISSUER, "exp": exp}, SECRET, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

# ---------------------- ROTAS ------------------------
@app.post(
    "/webhook/kiwify",
    summary="Recebe eventos do webhook da Kiwify para gerenciar assinaturas",
    description="Cria/renova/cancela assinaturas e retorna JWT quando ACTIVE."
)
async def kiwify(
    payload: KiwifyWebhook,
    x_kiwify_token: str | None = Header(None, alias="x-kiwify-token")
):
    logger.info(f"Webhook recebido: evento={payload.event} email={payload.data.customer_email}")

    # valida assinatura do webhook
    if WEBHOOK_TOKEN and x_kiwify_token != WEBHOOK_TOKEN:
        logger.warning("Token do webhook inválido")
        raise HTTPException(status_code=401, detail="unauthorized")

    event = payload.event
    email = payload.data.customer_email

    # ignora eventos não permitidos
    if event not in ALLOWED_EVENTS or not email:
        logger.info(f"Ignorado: evento={event} ou email ausente")
        return JSONResponse({"ok": True})

    # create/renew
    if event in ("subscription.created", "subscription.renewed"):
        token = gen_jwt(email, EXP_DAYS)
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=EXP_DAYS)
        await db.subscription.upsert(
            where={"email": email},
            data={
                "create": {"email": email, "jwt": token, "status": "ACTIVE", "expiresAt": expires},
                "update": {"jwt": token, "status": "ACTIVE", "expiresAt": expires},
            },
        )
        logger.info(f"Assinatura ACTIVE para {email}")
        return JSONResponse({"ok": True, "token": token})

    # cancel
    if event == "subscription.canceled":
        try:
            await db.subscription.update(where={"email": email}, data={"status": "INACTIVE"})
            logger.info(f"Assinatura INACTIVE para {email}")
        except Exception as e:
            logger.error(f"Erro ao cancelar {email}: {e}")
        return JSONResponse({"ok": True})

    # fallback
    return JSONResponse({"ok": True})

@app.get(
    "/a/{token}",
    summary="Valida JWT e redireciona para o Notion",
    description="Confere JWT + status no banco (ACTIVE e token igual ao salvo) e redireciona."
)
async def access(token: str):
    logger.info(f"Acesso solicitado com token: {token[:10]}...")

    # valida JWT
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"], issuer=ISSUER)
    except jwt.ExpiredSignatureError:
        logger.warning("Token expirado")
        raise HTTPException(403, os.environ.get("ERROR_MESSAGE_EXPIRED", "Sua assinatura expirou."))
    except jwt.InvalidTokenError as e:
        logger.warning(f"Token inválido: {e}")
        raise HTTPException(403, os.environ.get("ERROR_MESSAGE_INVALID", "Token invalido."))

    # confere no banco
    email = payload["sub"]
    try:
        rec = await db.subscription.find_unique(where={"email": email})
    except Exception as e:
        logger.error(f"Erro ao consultar {email}: {e}")
        raise HTTPException(500, "Erro interno no servidor")

    if not rec or rec.status != "ACTIVE" or rec.jwt != token:
        logger.warning(f"Token não encontrado/ativo para {email}")
        raise HTTPException(403, os.environ.get("ERROR_MESSAGE_INVALID", "Token invalido ou nao encontrado."))

    logger.info(f"Acesso autorizado para {email}")
    return RedirectResponse(NOTION_URL, status_code=REDIRECT_CODE)
