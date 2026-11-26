# Multi-stage Dockerfile for TypeScript MCP Server & CLI
# Builds with Node 24 (includes node:sqlite authorizer support) and runs as non-root appuser (UID 1001)

FROM node:24-slim AS builder
WORKDIR /app

RUN corepack enable pnpm

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src

RUN pnpm run build && pnpm prune --prod

FROM node:24-slim AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8000
ENV HOST=0.0.0.0

RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appgroup /app/data

COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.mcp-use ./.mcp-use
COPY --from=builder /app/dist ./dist
COPY examples/policies ./examples/policies

USER appuser
EXPOSE 8000

CMD ["node", ".mcp-use/build/index.js"]
