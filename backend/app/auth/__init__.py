from .handlers import AuthHandler, NOOPAuth, JWTAuthLocal, JWTAuthOIDC, UsernamePasswordAuth
from .settings import AuthType, settings


def get_auth_handler() -> AuthHandler:
    """Get the appropriate auth handler based on settings."""
    if settings.auth_type == AuthType.NOOP:
        return NOOPAuth()
    elif settings.auth_type == AuthType.JWT_LOCAL:
        return JWTAuthLocal()
    elif settings.auth_type == AuthType.JWT_OIDC:
        return JWTAuthOIDC()
    elif settings.auth_type == AuthType.USERNAME_PASSWORD:
        return UsernamePasswordAuth()
    else:
        raise ValueError(f"Unknown auth type: {settings.auth_type}")
