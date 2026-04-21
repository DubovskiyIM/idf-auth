# idf-auth

Identity plane для IDF SaaS. Выдаёт JWT (RS256) по magic-link, принимает tenant-signed invites от control plane.

См. [DEPLOYMENT.md](./DEPLOYMENT.md) после Task 21.

## Local dev

После реализации Task 2:
```bash
cp .env.example .env
npm install
npm run dev
```

(В текущей итерации — bootstrap package, `.env.example` появится с Task 2.)
