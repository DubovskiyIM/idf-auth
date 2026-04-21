FROM node:22-alpine AS base
WORKDIR /app

FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM base AS builder
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY drizzle ./drizzle
COPY scripts/migrate.mjs ./scripts/migrate.mjs
COPY package.json ./
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:4000/health || exit 1
CMD ["node", "dist/index.js"]
