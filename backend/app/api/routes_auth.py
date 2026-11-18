import hmac

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from backend.app.core.auth import (
    AUTH_COOKIE_NAME,
    AUTH_SESSION_MAX_AGE_SECONDS,
    configured_access_token,
    create_session_token,
    register_session,
    revoke_session,
    request_has_valid_access,
)
from backend.app.core.config import settings

router = APIRouter(tags=["Authentication"])


class AccessTokenRequest(BaseModel):
    token: str = Field(min_length=1, max_length=512)


@router.get("/auth/session")
def get_session(request: Request):
    return {
        "enabled": settings.API_AUTH_ENABLED,
        "configured": configured_access_token() is not None,
        "authenticated": (
            not settings.API_AUTH_ENABLED or request_has_valid_access(request)
        ),
    }


@router.post("/auth/session")
def create_session(payload: AccessTokenRequest, request: Request, response: Response):
    if not settings.API_AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="Authentication is disabled.")

    origin = request.headers.get("origin")
    if origin and origin not in settings.CORS_ORIGINS:
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")

    expected = configured_access_token()
    if expected is None:
        raise HTTPException(
            status_code=503,
            detail="API access is not configured. Set API_ACCESS_TOKEN to a random value of at least 32 characters.",
        )
    if not hmac.compare_digest(payload.token, expected):
        raise HTTPException(status_code=401, detail="Invalid access token.")

    session_token = create_session_token()
    register_session(session_token)
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=session_token,
        max_age=AUTH_SESSION_MAX_AGE_SECONDS,
        path=settings.API_PREFIX,
        secure=settings.AUTH_COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )
    return {"authenticated": True}


@router.delete("/auth/session")
def delete_session(request: Request, response: Response):
    if not settings.API_AUTH_ENABLED:
        return {"authenticated": True}

    origin = request.headers.get("origin")
    if origin and origin not in settings.CORS_ORIGINS:
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")

    revoke_session(request.cookies.get(AUTH_COOKIE_NAME))
    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        path=settings.API_PREFIX,
        secure=settings.AUTH_COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )
    return {"authenticated": False}
