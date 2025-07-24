from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os, jwt, datetime
from prisma import Prisma
from dotenv import load_dotenv

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
    customer_email: str

class KiwifyWebhook(BaseModel):
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
    return jwt.encode(
        {"sub": email, "iss": ISSUER, "exp": exp},
        SECRET,
        algorithm="HS256"
    )

@app.post("/webhook/kiwify")
async def kiwify(
    payload: KiwifyWebhook,
    x_kiwify_token: str | None = Header(None, alias="x-kiwify-token")
):
    # Validação do token do webhook
    if WEBHOOK_TOKEN and x_kiwify_token != WEBHOOK_TOKEN:
        raise HTTPException(401, "unauthorized")

    event = payload.event
    email = payload.data.customer_email

    # Ignora eventos não configurados ou sem email
    if event not in ALLOWED_EVENTS or not email:
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
        return JSONResponse({"ok": True, "token": token})

    # Cancelar assinatura
    if event == "subscription.canceled":
        try:
            await db.subscription.update(
                where={"email": email},
                data={"status": "INACTIVE"}
            )
        except Exception:
            pass
        return JSONResponse({"ok": True})

    return JSONResponse({"ok": True})

@app.get("/a/{token}")
async def access(token: str):
    # Valida JWT
    try:
        payload = jwt.decode(
            token,
            SECRET,
            algorithms=["HS256"],
            issuer=ISSUER
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            403,
            os.environ.get("ERROR_MESSAGE_EXPIRED", "Sua assinatura expirou.")
        )
    except Exception:
        raise HTTPException(
            403,
            os.environ.get("ERROR_MESSAGE_INVALID", "Token invalido.")
        )

    # Verifica status no banco
    email = payload["sub"]
    rec = await db.subscription.find_unique(where={"email": email})
    if not rec or rec.status != "ACTIVE" or rec.jwt != token:
        raise HTTPException(
            403,
            os.environ.get("ERROR_MESSAGE_INVALID", "Token invalido ou nao encontrado.")
        )

    # Redireciona para o Notion
    return RedirectResponse(NOTION_URL, status_code=REDIRECT_CODE)
