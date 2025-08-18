# Imagem base do Python
FROM python:3.11-slim

# Variáveis úteis (logs sem buffer e sem .pyc)
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Diretório de trabalho
WORKDIR /app

# Copia e instala as dependências primeiro (cache melhor)
COPY requirements.txt .
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copia o restante do projeto
COPY . .

# Porta da API
EXPOSE 8000

# Comando para iniciar a FastAPI
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
