# VPS Deployment runbook — idf-auth

**Target:** `auth.intent-design.tech` (Ubuntu 24.04 LTS VPS с ранее настроенными Docker + nginx + certbot). Local Postgres в compose (без Neon).

## Continuous Deploy

Push в `main` → CI passes → `.github/workflows/deploy.yml`:

1. Build `linux/amd64` image, push в `ghcr.io/dubovskiyim/idf-auth:latest` (+ tag по sha)
2. SSH в VPS → `cd /opt/idf-auth && docker compose pull auth && migrate (если есть scripts/migrate.mjs) && up -d auth` + smoke `/health`

**Manual override:** Actions tab → Deploy → Run workflow.

**One-time setup для CD:**

1. **SSH deploy-key** — тот же что для idf-studio (один ключ на VPS).
2. **GitHub Secrets** в idf-auth: `VPS_HOST=132.243.17.177`, `VPS_USER=root`, `VPS_SSH_KEY=<private key>`.
3. **GHCR public**: https://github.com/users/DubovskiyIM/packages/container/idf-auth/settings → Public.
4. **Compose** `/opt/idf-auth/docker-compose.yml`: `image: ghcr.io/dubovskiyim/idf-auth:latest`.

## Топология

```
Internet
   ↓ :443 (TLS)
nginx /etc/nginx/sites-enabled/auth.intent-design.tech
   ↓ proxy_pass http://127.0.0.1:4000
docker compose (idf-auth-pg + idf-auth) в /opt/idf-auth/
```

`idf-auth-pg` — `postgres:16-alpine` с volume `idf-auth_pgdata`. `idf-auth` — node:22-alpine runtime из multi-stage Dockerfile. Общаются через docker network `idf-auth_authnet`.

## Файлы на VPS

- `/opt/idf-auth/docker-compose.yml` — сервисы auth + postgres
- `/opt/idf-auth/.env` — secrets (chmod 600, owned by root)
- `/etc/nginx/sites-enabled/auth.intent-design.tech` — TLS reverse-proxy (certbot управляет SSL блоками)

## Первый deploy (сделан 2026-04-21)

1. **Ключ** добавлен в `/root/.ssh/authorized_keys`.
2. **DNS**: `auth.intent-design.tech → 132.243.17.177` (A-запись).
3. **Artefacts подготовлены локально** (`/tmp/idf-auth-deploy/`):
   - `docker-compose.yml`
   - `.env` c JWT keys (generated через `npm run keys:generate`), HMAC secret (`openssl rand -hex 32`), PG password (`openssl rand -hex 16`)
   - `auth.intent-design.tech.nginx` — HTTP-only, certbot дольёт HTTPS-блок
   - `idf-auth-amd64.tar` — `docker buildx build --platform linux/amd64 --load . && docker save`
4. **scp → VPS** → `docker load` → `docker tag idf-auth:amd64 idf-auth:dev`
5. `docker compose up -d` → контейнеры up
6. `docker compose exec auth node scripts/migrate.mjs` → 5 таблиц
7. `ln -s ... sites-enabled/` + `nginx -t && nginx -s reload`
8. `certbot --nginx -d auth.intent-design.tech --agree-tos -m <email>` → TLS
9. Smoke: `curl https://auth.intent-design.tech/health` → `{"status":"ok"}`

## Re-deploy (обновление кода)

```bash
# 1. Локально — пересобрать под amd64
cd ~/WebstormProjects/idf-auth
docker buildx build --platform linux/amd64 -t idf-auth:amd64 --load .

# 2. Экспорт + upload
docker save idf-auth:amd64 -o /tmp/idf-auth-amd64.tar
scp /tmp/idf-auth-amd64.tar root@132.243.17.177:/opt/idf-auth/

# 3. На VPS — reload image + recreate auth (БД не трогаем)
ssh root@132.243.17.177 '
  cd /opt/idf-auth
  docker load -i idf-auth-amd64.tar
  docker tag idf-auth:amd64 idf-auth:dev
  docker compose up -d --force-recreate auth
  sleep 3
  docker compose logs auth --tail=10
  curl -s http://127.0.0.1:4000/health
'
```

## Миграции

Применяются **из контейнера** — `migrate.mjs` цепляется к `DATABASE_URL` из env (docker network hostname `postgres`).

```bash
ssh root@132.243.17.177 'cd /opt/idf-auth && docker compose exec auth node scripts/migrate.mjs'
```

⚠ **Runner не идемпотентен** (см. follow-up в memory / Task 24 code review): второй запуск против уже-мигрированной БД упадёт на `relation ... already exists`. До первого breaking-change в schema — OK. Затем мигрировать на `drizzle-orm/node-postgres/migrator` с `__drizzle_migrations` tracking.

## Rotation JWT keys

M1 — single-key setup. Plановый rotation (M2):
1. Сгенерировать новую пару: `npm run keys:generate`
2. Добавить в `.env` как `JWT_PRIVATE_KEY_PEM_NEXT` / `_PUBLIC_KEY_PEM_NEXT`
3. M2-код: issue новой, verify обеими
4. После 30 дней (TTL старого JWT) — remove старую

## Подключение Resend (prod email)

Сейчас `EMAIL_DEV_MODE=true` — magic-link уходит только в `docker compose logs auth`.

1. `https://resend.com → API Keys → Create`
2. Подтвердить домен `intent-design.tech` через DNS (TXT запись).
3. На VPS:
   ```bash
   ssh root@132.243.17.177 '
     cd /opt/idf-auth
     sed -i "s/^EMAIL_DEV_MODE=true/EMAIL_DEV_MODE=false/" .env
     echo "RESEND_API_KEY=re_xxx" >> .env
     docker compose up -d --force-recreate auth
   '
   ```

## Переход с local Postgres на Neon

Если решишь перейти на managed БД:
1. Создать Neon проект → получить pooled connection string.
2. **Дамп + restore:**
   ```bash
   ssh root@132.243.17.177 'cd /opt/idf-auth && docker compose exec -T postgres pg_dump -U auth auth' > dump.sql
   psql "$NEON_URL" < dump.sql
   ```
3. Заменить `DATABASE_URL` в `.env` на Neon URI.
4. Убрать секцию `postgres` из `docker-compose.yml` (auth больше не зависит от локального сервиса).
5. `docker compose up -d --force-recreate auth` + удалить старый volume при желании.

## Backup local Postgres

Cron для ежедневного дампа в `/var/backups/idf-auth/`:

```bash
ssh root@132.243.17.177 '
  mkdir -p /var/backups/idf-auth
  cat > /etc/cron.daily/idf-auth-backup <<EOF
#!/bin/sh
cd /opt/idf-auth
docker compose exec -T postgres pg_dump -U auth auth | gzip > /var/backups/idf-auth/auth-\$(date +%Y%m%d).sql.gz
find /var/backups/idf-auth -name "auth-*.sql.gz" -mtime +14 -delete
EOF
  chmod +x /etc/cron.daily/idf-auth-backup
'
```

## Troubleshooting

- **`/health` пусто / 502**: `docker compose logs auth --tail=30`; часто — `idf-auth` в restart-loop из-за arch mismatch (arm64 vs amd64). Пересобрать с `--platform linux/amd64`.
- **Certbot renewal failed**: `certbot renew --dry-run` покажет причину. Порт 80 должен принимать ACME HTTP-01.
- **`rate-limit init failed` в логах на старте**: ожидаемо, если БД ещё не поднята к моменту `CREATE TABLE IF NOT EXISTS`. Самовосстанавливается на первом `/magic-link` запросе (но лучше проверить — `docker compose ps` оба healthy).
- **nginx returns 404 instead of proxying**: `ls -l /etc/nginx/sites-enabled/` — убедиться что symlink активен; `nginx -T | grep auth.intent`.
