"""Security layers for mcp-secure-db: RBAC middleware, BearerAuth, and SQL AST validator."""

from mcp_secure_db.security.rbac import (
    ADMIN_ONLY_TABLES,
    PII_COLUMNS_BY_TABLE,
    RESTRICTED_PII_COLUMNS,
    ROLE_ALLOWED_TOOLS,
    CallerPrincipal,
    HybridHTTPAuthMiddleware,
    RBACMiddleware,
    Role,
    SecureDBBearerAuthProvider,
    get_current_principal,
    resolve_principal_from_token,
    set_current_principal,
    warn_if_default_tokens_in_use,
)
from mcp_secure_db.security.validator import (
    SQLSecurityError,
    SQLValidationResult,
    SQLValidator,
)

__all__ = [
    "ADMIN_ONLY_TABLES",
    "PII_COLUMNS_BY_TABLE",
    "RESTRICTED_PII_COLUMNS",
    "ROLE_ALLOWED_TOOLS",
    "CallerPrincipal",
    "RBACMiddleware",
    "Role",
    "SQLSecurityError",
    "SQLValidationResult",
    "SQLValidator",
    "SecureDBBearerAuthProvider",
    "get_current_principal",
    "resolve_principal_from_token",
    "set_current_principal",
    "warn_if_default_tokens_in_use",
]
