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
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")

    logger.info("=" * 60)
    logger.info("Starting mcp-secure-db for Manufact Cloud")
    logger.info("4-Layer Sandboxed Analytical Database MCP Server")
    logger.info(f"Transport: {transport} | Host: {host} | Port: {port}")
    logger.info("Demo Tokens: token-viewer-demo, token-analyst-demo, token-admin-demo")
    logger.info("=" * 60)

    server.run(
        transport=transport,  # type: ignore[arg-type]
        host=host,
        port=port,
    )


if __name__ == "__main__":
    main()
