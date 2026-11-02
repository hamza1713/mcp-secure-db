# Multi-stage Dockerfile for TypeScript MCP Server
# Fully compliant with Manufact Cloud (Dockpack) runtime standards

FROM node:22-slim AS builder
WORKDIR /app

RUN corepack enable pnpm

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install

COPY tsconfig.json ./
COPY src ./src

RUN pnpm run build

FROM node:22-slim AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8000
ENV HOST=0.0.0.0

RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.mcp-use ./.mcp-use

USER appuser
EXPOSE 8000

CMD ["node", ".mcp-use/build/index.js"]
