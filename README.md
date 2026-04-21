# idf-auth

Identity plane для IDF SaaS. Выдаёт JWT (RS256) по magic-link, принимает tenant-signed invites от control plane.

## Endpoints

- `POST /magic-link` — issue nonce + email
- `GET /magic-link/callback?token=<nonce>` — verify, issue JWT
- `POST /invites` — tenant-signed; creates invite + email
- `GET /invites/accept?token=<nonce>` — accept invite, issue JWT
- `POST /revoke` — tenant-signed; revoke membership
- `GET /revocations?since=<iso>&domainSlug=<slug>` — pull endpoint для data plane
- `GET /.well-known/jwks.json` — JWKs
- `GET /health`, `GET /ready`

## Local dev

```bash
cp .env.example .env
# сгенерировать ключи:
npm run keys:generate  # скопировать PEM'ы в .env как JWT_*_PEM
# поднять Postgres:
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine
# применить миграции:
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres npm run db:migrate
# старт:
npm run dev
```

## Тесты

```bash
npm test           # unit + integration (testcontainers)
npm run smoke      # E2E против spawned server + testcontainer Postgres
```

### Testcontainers + Ryuk

Если `beforeAll` зависает на 60 сек на cold-start — включи skip для Ryuk daemon:
```bash
echo 'ryuk.disabled=true' >> ~/.testcontainers.properties
```

## Deploy

См. [DEPLOYMENT.md](./DEPLOYMENT.md).
