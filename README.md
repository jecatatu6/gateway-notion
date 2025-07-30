# Projeto de Gerenciamento de Assinaturas com FastAPI e Prisma

Este projeto é uma API desenvolvida em FastAPI que gerencia assinaturas de clientes via webhook da Kiwify. Ele gera tokens JWT para assinantes ativos, armazena informações de assinatura em um banco de dados PostgreSQL acessado via Prisma, e redireciona usuários autenticados para uma URL do Notion.

## Funcionalidades principais

- Recebe eventos de webhook da Kiwify para criação, renovação e cancelamento de assinaturas.
- Gera tokens JWT com validade configurável para assinantes ativos.
- Armazena e atualiza o status das assinaturas no banco de dados.
- Endpoint para validação do token JWT e redirecionamento para uma URL configurada.
- Middleware CORS configurado para permitir chamadas de qualquer origem (útil para testes).

## Variáveis de ambiente necessárias

- `JWT_SECRET`: Segredo para assinatura dos tokens JWT.
- `JWT_ISSUER`: Emissor dos tokens JWT.
- `NOTION_URL`: URL para onde os usuários autenticados serão redirecionados.
- `REDIRECT_HTTP_CODE`: Código HTTP para redirecionamento (padrão: 302).
- `ALLOWED_EVENTS`: Eventos permitidos do webhook, separados por vírgula (padrão: `subscription.created,subscription.renewed,subscription.canceled`).
- `WEBHOOK_VERIFY_SECRET`: Token secreto para validação do webhook (opcional).
- `JWT_EXP_DAYS`: Quantidade de dias para expiração do token JWT (padrão: 365).
- `DATABASE_URL`: URL de conexão com o banco PostgreSQL (com pooling).
- `DIRECT_URL`: URL de conexão direta com o banco PostgreSQL (para migrações).
- `ERROR_MESSAGE_EXPIRED`: Mensagem de erro para token expirado (opcional).
- `ERROR_MESSAGE_INVALID`: Mensagem de erro para token inválido (opcional).

## Como rodar a aplicação

1. Configure as variáveis de ambiente acima, preferencialmente em um arquivo `.env`.
2. Instale as dependências do projeto (FastAPI, Prisma Client, etc.).
3. Execute as migrações do Prisma para criar a tabela `Subscription` no banco.
4. Inicie a aplicação FastAPI (exemplo: `uvicorn app:app --reload`).
5. Configure o webhook da Kiwify para apontar para o endpoint `/webhook/kiwify`.

## Próximos passos recomendados

- Criar testes automatizados para as rotas principais.
- Adicionar documentação Swagger/OpenAPI mais detalhada.
- Implementar logs para monitoramento e auditoria.
- Melhorar tratamento de erros e validação de dados.
- Avaliar segurança do webhook e tokens JWT.
- Criar scripts para facilitar migrações e deploy.

---
Este README serve como ponto de partida para entender e evoluir o projeto.