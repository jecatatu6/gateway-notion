# Imagem base do Python
FROM python:3.13-slim

# Diretório de trabalho
WORKDIR /app

# Copia e instala as dependências primeiro (melhora cache)
COPY requirements.txt .
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copia o restante do projeto
COPY . .

# Gera o Prisma Client dentro da imagem (antes do CMD)

# Comando para iniciar a FastAPI
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9001"]

