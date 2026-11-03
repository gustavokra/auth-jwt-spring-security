# auth-jwt-spring-security

API de autenticação e autorização com **Spring Boot**, **JWT**, **Spring Security** e práticas de **Security by Design**.

Projeto focado em login seguro: proteção contra força bruta, ciclo de vida de tokens, auditoria e configuração orientada a secrets por ambiente.

---

## Stack

- Java 21
- Spring Boot 4
- Spring Security (stateless)
- JWT (Auth0 java-jwt) — access token
- Refresh token opaco (Redis)
- PostgreSQL + Flyway
- Redis (rate limit, refresh tokens, denylist)
- Bucket4j (rate limiting)
- Google reCAPTCHA v2
- Docker Compose (Postgres + Redis)

---

## Funcionalidades de segurança

| Área | Implementação |
|------|----------------|
| Autenticação | Login com e-mail/senha, BCrypt |
| Tokens | Access JWT curto (`jti`) + refresh opaco no Redis |
| Sessão | Logout com denylist do access + invalidação do refresh |
| Autorização | Roles `USER` / `ADMIN` + `@PreAuthorize` |
| Brute force | Rate limit (login, register, refresh), account lock, CAPTCHA |
| Senha | Mín. 8 caracteres, maiúscula, minúscula, número e símbolo |
| Headers | nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS |
| CORS | Origins configuráveis via env |
| Privacidade | Resposta genérica no register (anti-enumeração de e-mail) |
| Auditoria | Logger `SECURITY_AUDIT` (login, lock, captcha, 429, refresh, logout) |
| Schema | Flyway + `ddl-auto=validate` |

---

## Pré-requisitos

- JDK 21+
- Maven 3.9+
- Docker e Docker Compose
- Conta reCAPTCHA (site key + secret) para o login

---

## Subir infraestrutura

```bash
docker compose up -d
```

Sobe PostgreSQL e Redis (Redis com senha via `.env`).

---

## Configuração

Crie um arquivo `.env` na raiz (não versionado):

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=tutorialseguranca
DB_USERNAME=seu_usuario
DB_PASSWORD=sua_senha

JWT_SECRET=gere_com_openssl_rand_hex_32

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=sua_senha_redis

RECAPTCHA_SECRET=sua_secret_do_google

CORS_ORIGINS=http://localhost:4200,http://localhost:5500,http://127.0.0.1:5500
```

Gerar secret JWT:

```bash
openssl rand -hex 32
```

Em produção, defina por exemplo:

```env
CORS_ORIGINS=https://seu-frontend.com
```

---

## Rodar a API

```bash
./mvnw spring-boot:run
```

Por padrão a API sobe em `http://localhost:8080`.

---

## Endpoints principais

| Método | Path | Auth | Descrição |
|--------|------|------|-----------|
| `POST` | `/api/v1/auth/register` | Pública | Registro de usuário |
| `POST` | `/api/v1/auth/login` | Pública + CAPTCHA | Login → `accessToken` + `refreshToken` |
| `POST` | `/api/v1/auth/refresh` | Pública | Renova tokens (rotação do refresh) |
| `POST` | `/api/v1/auth/logout` | Access no header (opcional) | Revoga access + refresh |
| `POST` | `/api/v1/admin/register` | `ROLE_ADMIN` | Cria outro admin |

### Register

```json
{
  "nome": "Gustavo",
  "email": "user@email.com",
  "senha": "Senha123!"
}
```

### Login

```json
{
  "email": "user@email.com",
  "password": "Senha123!",
  "captchaToken": "token-do-recaptcha"
}
```

### Refresh

```json
{
  "refreshToken": "..."
}
```

Rotas protegidas: header `Authorization: Bearer <accessToken>`.

---

## Fluxo de tokens

```text
Login
  → access JWT (~15 min, com jti)
  → refresh opaco (Redis, TTL ~7 dias)

API
  → só o access no header Authorization

Access expirado
  → POST /auth/refresh → novo access (+ novo refresh)

Logout
  → jti do access na denylist (Redis)
  → refresh removido do Redis
```

---

## Testes

```bash
./mvnw test
```

Os testes de segurança cobrem, entre outros:

- acesso sem token (401)
- CAPTCHA inválido (400)
- register + login com tokens
- USER acessando endpoint admin (403)
- refresh inválido (401)
- logout e rejeição do access (denylist)

> **Nota:** os testes usam a infraestrutura local (Postgres/Redis). Mantenha o `docker compose` no ar. E-mails de teste são gerados de forma única para não colidir com dados antigos.

---

## Estrutura relevante

```text
src/main/java/com/dev/security/
├── config/
│   ├── SecurityConfig.java          # filter chain, headers, method security
│   ├── SecurityFilter.java          # validação JWT
│   ├── CorsConfig.java
│   ├── accountLock/                 # lock + eventos de auth
│   ├── audit/                       # SECURITY_AUDIT
│   ├── captcha/
│   ├── rateLimiting/                # Bucket4j + Redis
│   └── token/                       # access, refresh, denylist
├── controller/
│   ├── AuthController.java
│   └── AdminController.java
├── entity/
│   └── User.java
└── ...
```

---

## Segurança — decisões importantes

1. **Access curto + refresh opaco** reduz a janela se o JWT vazar e permite logout real.
2. **Rate limit no edge** (filtro) evita processar login/CAPTCHA sob flood.
3. **Account lock** limita tentativas por conta; rate limit limita por IP.
4. **CAPTCHA** no login encarece automação.
5. **Secrets só em env** — nunca commitados.
6. **Register genérico** evita enumeração pública de e-mails.

---

## Licença

Este repositório é um projeto de estudo/portfólio. Ajuste a licença conforme sua preferência.
```