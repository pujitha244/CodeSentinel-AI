import hashlib
import hmac
import secrets
import time
from typing import Optional, Tuple

from fastapi import Request

from backend.app.core.config import settings
from backend.app.core.database import SessionLocal

AUTH_COOKIE_NAME = "codesentinel_session"
MIN_ACCESS_TOKEN_LENGTH = 32
AUTH_SESSION_MAX_AGE_SECONDS = 12 * 60 * 60


def configured_access_token() -> Optional[str]:
    token = settings.API_ACCESS_TOKEN
    return token if len(token) >= MIN_ACCESS_TOKEN_LENGTH else None


def request_has_valid_access(request: Request) -> bool:
    expected = configured_access_token()
    if expected is None:
        return False

    authorization = request.headers.get("authorization", "")
    bearer_token = None
    if authorization.startswith("Bearer "):
        bearer_token = authorization[7:]

    if bearer_token is not None and hmac.compare_digest(bearer_token, expected):
        return True

    return is_valid_session_token(request.cookies.get(AUTH_COOKIE_NAME), expected)


def create_session_token(now: Optional[int] = None) -> str:
    expected = configured_access_token()
    if expected is None:
        raise ValueError("API access token is not configured.")
    issued_at = int(time.time()) if now is None else now
    nonce = secrets.token_urlsafe(18)
    message = f"{issued_at}.{nonce}"
    signature = hmac.new(
        expected.encode("utf-8"), message.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return f"{message}.{signature}"


def _session_token_payload(
    token: Optional[str],
) -> Optional[Tuple[str, int, str, str]]:
    if token is None:
        return None
    try:
        issued_at_text, nonce, signature = token.split(".", maxsplit=2)
        issued_at = int(issued_at_text)
    except (ValueError, TypeError):
        return None

    return issued_at_text, issued_at, nonce, signature


def _valid_signed_session(
    token: Optional[str], expected: Optional[str], now: Optional[int] = None
) -> Optional[Tuple[str, int]]:
    if expected is None or token is None:
        return None

    payload = _session_token_payload(token)
    if payload is None:
        return None
    issued_at_text, issued_at, nonce, signature = payload

    current_time = int(time.time()) if now is None else now
    age = current_time - issued_at
    if age < 0 or age >= AUTH_SESSION_MAX_AGE_SECONDS:
        return None

    message = f"{issued_at_text}.{nonce}"
    expected_signature = hmac.new(
        expected.encode("utf-8"), message.encode("ascii"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None

    session_id = hashlib.sha256(nonce.encode("ascii")).hexdigest()
    return session_id, issued_at


def register_session(token: str) -> None:
    payload = _session_token_payload(token)
    if payload is None:
        raise ValueError("Invalid generated session token.")
    _, issued_at, nonce, _ = payload
    from backend.app.models.models import AuthSession

    db = SessionLocal()
    try:
        now = int(time.time())
        db.query(AuthSession).filter(AuthSession.expires_at <= now).delete()
        db.add(
            AuthSession(
                id=hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                expires_at=issued_at + AUTH_SESSION_MAX_AGE_SECONDS,
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def revoke_session(token: Optional[str]) -> None:
    payload = _session_token_payload(token)
    if payload is None:
        return
    _, _, nonce, _ = payload
    from backend.app.models.models import AuthSession

    db = SessionLocal()
    try:
        session = db.query(AuthSession).filter(
            AuthSession.id == hashlib.sha256(nonce.encode("ascii")).hexdigest()
        ).first()
        if session is not None and session.revoked_at is None:
            session.revoked_at = int(time.time())
            db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def is_valid_session_token(
    token: Optional[str],
    expected: Optional[str] = None,
    now: Optional[int] = None,
) -> bool:
    expected = configured_access_token() if expected is None else expected
    valid_payload = _valid_signed_session(token, expected, now)
    if valid_payload is None:
        return False

    session_id, issued_at = valid_payload
    current_time = int(time.time()) if now is None else now
    from backend.app.models.models import AuthSession

    db = SessionLocal()
    try:
        session = db.query(AuthSession).filter(
            AuthSession.id == session_id,
            AuthSession.expires_at > current_time,
            AuthSession.revoked_at.is_(None),
        ).first()
        return session is not None and session.expires_at == issued_at + AUTH_SESSION_MAX_AGE_SECONDS
    finally:
        db.close()
