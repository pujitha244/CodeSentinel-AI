import pytest
import time
from fastapi.testclient import TestClient

from backend.app.core.auth import (
    AUTH_COOKIE_NAME,
    AUTH_SESSION_MAX_AGE_SECONDS,
    create_session_token,
    is_valid_session_token,
    register_session,
)
from backend.app.core.config import settings
from backend.app.main import app

TEST_TOKEN = "test-only-access-token-with-at-least-32-characters"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "API_ACCESS_TOKEN", TEST_TOKEN)
    monkeypatch.setattr(settings, "API_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "AUTH_COOKIE_SECURE", False)
    with TestClient(app) as test_client:
        yield test_client


def test_protected_routes_and_api_docs_require_authentication(client):
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/openapi.json").status_code == 401


def test_authentication_is_disabled_by_default_and_api_remains_open(monkeypatch):
    monkeypatch.setattr(settings, "API_AUTH_ENABLED", False)
    monkeypatch.setattr(settings, "API_ACCESS_TOKEN", "")
    with TestClient(app) as client:
        assert client.get("/api/auth/session").json() == {
            "enabled": False,
            "configured": False,
            "authenticated": True,
        }
        assert client.get("/api/projects").status_code == 200
        assert client.get("/api/openapi.json").status_code == 200


def test_token_login_uses_http_only_cookie_and_signout_revokes_session(client):
    rejected = client.post("/api/auth/session", json={"token": "wrong"})
    assert rejected.status_code == 401
    assert "wrong" not in rejected.text

    login = client.post("/api/auth/session", json={"token": TEST_TOKEN})
    assert login.status_code == 200
    cookie = login.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/api" in cookie
    assert f"max-age={AUTH_SESSION_MAX_AGE_SECONDS}" in cookie
    assert TEST_TOKEN not in login.headers["set-cookie"]
    assert TEST_TOKEN not in login.text
    session_token = client.cookies.get(AUTH_COOKIE_NAME)
    assert client.get("/api/projects").status_code == 200

    logout = client.delete("/api/auth/session", headers={"origin": "http://localhost:5173"})
    assert logout.status_code == 200
    client.cookies.set(AUTH_COOKIE_NAME, session_token)
    assert client.get("/api/projects").status_code == 401


def test_session_cookie_is_signed_and_expires_server_side(client):
    issued_at = int(time.time())
    session_token = create_session_token(now=issued_at)
    register_session(session_token)
    assert is_valid_session_token(
        session_token, TEST_TOKEN, now=issued_at + AUTH_SESSION_MAX_AGE_SECONDS - 1
    )
    assert not is_valid_session_token(
        session_token, TEST_TOKEN, now=issued_at + AUTH_SESSION_MAX_AGE_SECONDS
    )
    assert not is_valid_session_token(session_token, TEST_TOKEN, now=issued_at - 1)
    assert not is_valid_session_token(f"{issued_at}.forged", TEST_TOKEN, now=issued_at)

    expired_issue_time = int(time.time()) - AUTH_SESSION_MAX_AGE_SECONDS
    expired = create_session_token(now=expired_issue_time)
    register_session(expired)
    client.cookies.set(AUTH_COOKIE_NAME, expired)
    assert client.get("/api/projects").status_code == 401


def test_missing_or_short_token_fails_closed(client, monkeypatch):
    monkeypatch.setattr(settings, "API_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "API_ACCESS_TOKEN", "too-short")

    status = client.get("/api/auth/session")
    assert status.json() == {
        "enabled": True,
        "configured": False,
        "authenticated": False,
    }
    assert client.get("/api/projects").status_code == 503
    assert client.post("/api/auth/session", json={"token": "too-short"}).status_code == 503


def test_auth_rejects_untrusted_origins(client):
    response = client.post(
        "/api/auth/session",
        json={"token": TEST_TOKEN},
        headers={"origin": "https://attacker.example"},
    )
    assert response.status_code == 403


def test_all_registered_protected_api_routes_reject_missing_authentication(client):
    import re

    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set())
        if not path.startswith("/api/") or path in {
            "/api/health",
            "/api/auth/session",
        }:
            continue
        path = re.sub(r"\{[^}]+\}", "test-id", path)
        method = next((candidate for candidate in methods if candidate != "OPTIONS"), None)
        if method is None:
            continue
        response = client.request(method, path)
        assert response.status_code == 401, f"{method} {path} was not protected"

    login = client.post("/api/auth/session", json={"token": TEST_TOKEN})
    assert login.status_code == 200
    response = client.post(
        "/api/projects/demo",
        headers={"origin": "https://attacker.example"},
    )
    assert response.status_code == 403
