# Deployment runbook — idf-auth

**Решение про Postgres:** используем Neon (managed) — auto-backup, $0 до 10GB. Fly machine — только для Node app.

## Первый deploy

### 1. Создать Neon Postgres

```bash
# https://console.neon.tech — создать проект "idf-auth"
# скопировать pooled connection string
export DATABASE_URL='postgres://user:pwd@host.neon.tech/db?sslmode=require'
```

### 2. Сгенерировать JWT keypair

```bash
npm run keys:generate
# сохранить output в ~/.idf-auth-secrets/ (не в git!)
```

### 3. Сгенерировать tenant HMAC secret

```bash
node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))'
# сохранить — этот же secret нужен будет в control plane
export TENANT_HMAC_SECRET="<hex>"
```

### 4. Получить Resend API key

```bash
# https://resend.com → API Keys → Create
# затем подтвердить домен idf.dev (DNS verification)
```

### 5. Создать Fly app

```bash
flyctl launch --no-deploy --name idf-auth
# если имя занято — взять другое и обновить fly.toml
```

### 6. Set secrets

```bash
flyctl secrets set DATABASE_URL="$DATABASE_URL"
flyctl secrets set JWT_PRIVATE_KEY_PEM="$(cat ~/.idf-auth-secrets/jwt.priv.pem)"
flyctl secrets set JWT_PUBLIC_KEY_PEM="$(cat ~/.idf-auth-secrets/jwt.pub.pem)"
flyctl secrets set TENANT_HMAC_SECRET="$TENANT_HMAC_SECRET"
flyctl secrets set RESEND_API_KEY="re_xxx"
```

### 7. Мигрировать БД

```bash
# локально против production DATABASE_URL
npm run db:migrate
```

### 8. Deploy

```bash
flyctl deploy
```

### 9. DNS

```bash
# в registrar:
# A    auth.idf.dev → Fly IPv4 (см. flyctl ips list)
# AAAA auth.idf.dev → Fly IPv6
flyctl certs create auth.idf.dev
```

### 10. Smoke

```bash
curl https://auth.idf.dev/health
curl https://auth.idf.dev/.well-known/jwks.json
```

## Rotation JWT keys (M2+)

Не поддерживается в M1 single-key setup. Для планового rotation:
1. Сгенерировать новую пару.
2. Добавить её как `JWT_PRIVATE_KEY_PEM_NEXT` / `_PUBLIC_KEY_PEM_NEXT`.
3. Issue — новой, verify — обеими (M2 код).
4. После 30 дней (TTL старого JWT) — remove старую.

## Troubleshooting

- **500 на /magic-link**: проверить Resend verify status для домена `idf.dev`.
- **`rate_limit_log` таблица не найдена**: `rate-limiter-flexible` создаёт её при первом `consume`; предупреждение `rate-limit init failed` в логах на старте — ожидаемо, если DB ещё не доступна.
- **Revocations возвращает пусто**: убедиться что control plane шлёт `?domainSlug=` query.
- **Контейнер падает сразу после `auth plane started`**: pre-0.1.1 версии падали на bad DATABASE_URL из-за unhandled rate-limiter init rejection. Fix — коммит `492b085`. Убедиться что деплой выше этого SHA.
