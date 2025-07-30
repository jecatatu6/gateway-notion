from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pydantic.networks import EmailStr
import os, jwt, datetime
from prisma import Prisma
from dotenv import load_dotenv
import logging

# Configuração básica do logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Carrega variáveis de ambiente do .env
load_dotenv()

# Instância do FastAPI
app = FastAPI()

# Middleware CORS — permite chamadas de qualquer origem (útil para testes no Swagger UI)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cliente Prisma
db = Prisma()

# Modelos Pydantic para payload do webhook
class KiwifyData(BaseModel):
    """Modelo para os dados do cliente no webhook da Kiwify."""
    customer_email: EmailStr

class KiwifyWebhook(BaseModel):
    """Modelo para o payload do webhook da Kiwify."""
    event: str
    data: KiwifyData

# Eventos de startup/shutdown para conectar ao banco
@app.on_event("startup")
async def startup():
    await db.connect()

@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()

# Leitura de configurações
SECRET = os.environ["JWT_SECRET"]
ISSUER = os.environ["JWT_ISSUER"]
NOTION_URL = os.environ["NOTION_URL"]
REDIRECT_CODE = int(os.environ.get("REDIRECT_HTTP_CODE", "302"))
ALLOWED_EVENTS = set(os.environ.get(
    "ALLOWED_EVENTS",
    "subscription.created,subscription.renewed,subscription.canceled"
).split(","))
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_VERIFY_SECRET")
EXP_DAYS = int(os.environ.get("JWT_EXP_DAYS", "365"))

def gen_jwt(email: str, days: int) -> str:
    """Gera um JWT com claim sub=email, iss=ISSUER e exp daqui a `days` dias."""
    exp = datetime.datetime.utcnow() + datetime.timedelta(days=days)
    token = jwt.encode(
        {"sub": email, "iss": ISSUER, "exp": exp},
        SECRET,
        algorithm="HS256"
    )
    # jwt.encode retorna str no PyJWT 2.x, mas bytes em versões antigas
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

@app.post(
    "/webhook/kiwify",
    summary="Recebe eventos do webhook da Kiwify para gerenciar assinaturas",
    description="Processa eventos de criação, renovação e cancelamento de assinaturas, gerando tokens JWT para assinantes ativos."
)
async def kiwify(
    payload: KiwifyWebhook,
    x_kiwify_token: str | None = Header(None, alias="x-kiwify-token")
):
    logger.info(f"Recebido webhook: evento={payload.event}, email={payload.data.customer_email}")

    # Validação do token do webhook
    if WEBHOOK_TOKEN and x_kiwify_token != WEBHOOK_TOKEN:
        logger.warning("Token do webhook inválido")
        raise HTTPException(401, "unauthorized")

    event = payload.event
    email = payload.data.customer_email

    # Ignora eventos não configurados ou sem email
    if event not in ALLOWED_EVENTS or not email:
        logger.info(f"Evento ignorado: {event} ou email ausente")
        return JSONResponse({"ok": True})

    # Criar/renovar assinatura
    if event in ("subscription.created", "subscription.renewed"):
        token = gen_jwt(email, EXP_DAYS)
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=EXP_DAYS)
        await db.subscription.upsert(
            where={"email": email},
            data={
                "create": {
                    "email": email,
                    "jwt": token,
                    "status": "ACTIVE",
                    "expiresAt": expires
                },
                "update": {
                    "jwt": token,
                    "status": "ACTIVE",
                    "expiresAt": expires
                }
            }
        )
        logger.info(f"Assinatura criada/renovada para {email}")
        return JSONResponse({"ok": True, "token": token})

    # Cancelar assinatura
    if event == "subscription.canceled":
        try:
            await db.subscription.update(
                where={"email": email},
                data={"status": "INACTIVE"}
            )
            logger.info(f"Assinatura cancelada para {email}")
        except Exception as e:
            logger.error(f"Erro ao cancelar assinatura para {email}: {e}")
        return JSONResponse({"ok": True})

    return JSONResponse({"ok": True})

@app.get(
    "/a/{token}",
    summary="Valida token JWT e redireciona para a URL do Notion",
    description="Verifica se o token JWT é válido, ativo e não expirado, e redireciona o usuário autenticado."
)
async def access(token: str):
    logger.info(f"Requisição de acesso com token: {token[:10]}...")

    # Valida JWT
    try:
        payload = jwt.decode(
            token,
            SECRET,
            algorithms=["HS256"],
            issuer=ISSUER
        )
    except jwt.ExpiredSignatureError:
        logger.warning("Token expirado")
        raise HTTPException(
            403,
            os.environ.get("ERROR_MESSAGE_EXPIRED", "Sua assinatura expirou.")
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Token inválido: {e}")
        raise HTTPException(
            403,
            os.environ.get("ERROR_MESSAGE_INVALID", "Token invalido.")
        )
    except Exception as e:
        logger.error(f"Erro inesperado ao validar token: {e}")
        raise HTTPException(
            500,
            "Erro interno no servidor"
        )

    # Verifica status no banco
    email = payload["sub"]
    try:
        rec = await db.subscription.find_unique(where={"email": email})
    except Exception as e:
        logger.error(f"Erro ao consultar banco para email {email}: {e}")
        raise HTTPException(
            500,
            "Erro interno no servidor"
        )
    if not rec or rec.status != "ACTIVE" or rec.jwt != token:
        logger.warning(f"Token inválido ou não encontrado para email: {email}")
        raise HTTPException(
            403,
            os.environ.get("ERROR_MESSAGE_INVALID", "Token invalido ou nao encontrado.")
        )

    logger.info(f"Acesso autorizado para email: {email}")
    # Redireciona para o Notion
    return RedirectResponse(NOTION_URL, status_code=REDIRECT_CODE)
