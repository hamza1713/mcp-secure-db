"""Dockpack / Manufact Cloud entrypoint for mcp-secure-db."""

from __future__ import annotations

import logging
import os
import sys

from mcp_secure_db.server import create_server, server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mcp_secure_db")


def main() -> None:
    # Default to 127.0.0.1 for local browser compatibility (avoids ERR_ADDRESS_INVALID on 0.0.0.0).
    # Dockerfile explicitly sets HOST="0.0.0.0" for cloud container deployments.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")

    browser_host = "localhost" if host in ("0.0.0.0", "127.0.0.1") else host

    logger.info("=" * 65)
    logger.info("🚀 Starting mcp-secure-db (Manufact Cloud & Inspector Ready)")
    logger.info("🛡️  4-Layer Sandboxed Analytical Database MCP Server")
    logger.info(f"🌐 Transport: {transport} | Bind: {host}:{port}")
    logger.info(f"🔍 MCP Inspector: http://{browser_host}:{port}/inspector")
    logger.info(f"📚 API Docs:      http://{browser_host}:{port}/docs")
    logger.info(f"🔌 MCP Endpoint:  http://{browser_host}:{port}/mcp")
    logger.info("🔑 Demo Tokens:   token-viewer-demo, token-analyst-demo, token-admin-demo")
    logger.info("=" * 65)

    server.run(
        transport=transport,  # type: ignore[arg-type]
        host=host,
        port=port,
    )


if __name__ == "__main__":
    main()
