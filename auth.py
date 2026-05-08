"""
auth.py – NetWatch authentication layer
Provides:
  - Password hashing (bcrypt)
  - JWT token issuance + validation
  - Flask decorators: @require_auth, @optional_auth
  - /api/auth/login  and  /api/auth/refresh  endpoints

Configuration via environment variables:
  NETWATCH_SECRET_KEY   – JWT signing secret (CHANGE IN PRODUCTION)
  NETWATCH_ADMIN_USER   – default admin username (default: admin)
  NETWATCH_ADMIN_PASS   – default admin password (default: netwatch)
  NETWATCH_JWT_EXPIRY   – token lifetime in seconds (default: 86400 = 24h)
  NETWATCH_AUTH_ENABLED – set to "false" to disable auth entirely (dev mode)
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Optional

import bcrypt
import jwt
from flask import Flask, request, jsonify, g

from logger import get_logger

log = get_logger("auth")

# ─── Config ───────────────────────────────────────────────────────────────────

SECRET_KEY    = os.getenv("NETWATCH_SECRET_KEY",    "netwatch-dev-secret-change-me")
ADMIN_USER    = os.getenv("NETWATCH_ADMIN_USER",    "admin")
ADMIN_PASS    = os.getenv("NETWATCH_ADMIN_PASS",    "netwatch")
JWT_EXPIRY    = int(os.getenv("NETWATCH_JWT_EXPIRY", "86400"))
AUTH_ENABLED  = os.getenv("NETWATCH_AUTH_ENABLED",  "true").lower() != "false"

# ─── In-memory user store (single admin for v1) ────────────────────────────
# Extend this to DB-backed users if needed.

def _hash(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def _verify(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed)
    except Exception:
        return False

# Built at startup so the hash cost is paid once
_USERS: dict[str, bytes] = {
    ADMIN_USER: _hash(ADMIN_PASS)
}


# ─── JWT helpers ─────────────────────────────────────────────────────────────

def _issue_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def _decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        log.warn("Expired JWT received")
        return None
    except jwt.InvalidTokenError as e:
        log.warn("Invalid JWT", error=str(e))
        return None


def _extract_token() -> Optional[str]:
    """Extract Bearer token from Authorization header or 'token' query param."""
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:]
    return request.args.get("token")


# ─── Decorators ──────────────────────────────────────────────────────────────

def require_auth(fn):
    """Require a valid JWT. Returns 401 if missing/invalid."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not AUTH_ENABLED:
            g.user = "anonymous"
            return fn(*args, **kwargs)
        token = _extract_token()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        payload = _decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        g.user = payload["sub"]
        return fn(*args, **kwargs)
    return wrapper


def optional_auth(fn):
    """Attach user to g if token present, but don't reject unauthenticated requests."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = _extract_token()
        g.user = None
        if token:
            payload = _decode_token(token)
            if payload:
                g.user = payload["sub"]
        return fn(*args, **kwargs)
    return wrapper


# ─── Flask route registration ─────────────────────────────────────────────────

def register_auth_routes(app: Flask) -> None:

    @app.post("/api/auth/login")
    def auth_login():
        data     = request.json or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"error": "username and password required"}), 400

        hashed = _USERS.get(username)
        if not hashed or not _verify(password, hashed):
            log.warn("Failed login attempt", username=username,
                     ip=request.remote_addr)
            return jsonify({"error": "Invalid credentials"}), 401

        token = _issue_token(username)
        log.info("Login successful", username=username, ip=request.remote_addr)
        return jsonify({
            "token":      token,
            "expires_in": JWT_EXPIRY,
            "username":   username,
        })

    @app.post("/api/auth/refresh")
    @require_auth
    def auth_refresh():
        token = _issue_token(g.user)
        return jsonify({"token": token, "expires_in": JWT_EXPIRY})

    @app.get("/api/auth/me")
    @require_auth
    def auth_me():
        return jsonify({"username": g.user, "auth_enabled": AUTH_ENABLED})

    @app.post("/api/auth/change-password")
    @require_auth
    def auth_change_password():
        data         = request.json or {}
        current_pass = data.get("current_password", "")
        new_pass     = data.get("new_password", "")

        if not current_pass or not new_pass:
            return jsonify({"error": "current_password and new_password required"}), 400
        if len(new_pass) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400

        hashed = _USERS.get(g.user)
        if not hashed or not _verify(current_pass, hashed):
            return jsonify({"error": "Current password is incorrect"}), 401

        _USERS[g.user] = _hash(new_pass)
        log.info("Password changed", username=g.user)
        return jsonify({"ok": True})


def is_auth_enabled() -> bool:
    return AUTH_ENABLED
