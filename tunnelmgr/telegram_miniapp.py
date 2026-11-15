"""Telegram Mini App authentication helpers.

The Mini App is intentionally separate from the main panel UI.  Telegram's
signed init data is verified server-side before a normal avaTUN session is
issued, so the Mini App can reuse the existing permission checks and API.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import time
import urllib.parse


def config_path():
    return pathlib.Path(os.environ.get("AVATUN_TELEGRAM_CONFIG", "/etc/avatun/telegram.json"))


def load_config(path=None):
    path = pathlib.Path(path or config_path())
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or not isinstance(data.get("bot_token"), str) or not data["bot_token"]:
        raise ValueError("Telegram bot configuration is incomplete")
    return data


def verify_init_data(init_data, bot_token, now=None, max_age=86400):
    """Return Telegram init-data fields after authenticating the signature."""
    if not isinstance(init_data, str) or len(init_data.encode("utf-8")) > 8192:
        raise ValueError("Telegram init data is invalid")
    fields = urllib.parse.parse_qs(init_data, keep_blank_values=True, strict_parsing=True)
    supplied = fields.pop("hash", [""])[0]
    if not supplied or len(supplied) != 64:
        raise ValueError("Telegram init data signature is missing")
    pairs = []
    for key, values in fields.items():
        if len(values) != 1:
            raise ValueError("Telegram init data contains duplicate fields")
        pairs.append((key, values[0]))
    check = "\n".join(f"{key}={value}" for key, value in sorted(pairs))
    secret = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    expected = hmac.new(secret, check.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("Telegram init data signature is invalid")
    try:
        auth_date = int(fields.get("auth_date", [""])[0])
        user_values = fields.get("user", ["{}"])
        user = json.loads(user_values[0])
        user_id = int(user["id"])
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        raise ValueError("Telegram init data user is invalid") from error
    now = int(time.time() if now is None else now)
    if auth_date > now + 60 or now - auth_date > max_age:
        raise ValueError("Telegram init data has expired")
    if user_id <= 0:
        raise ValueError("Telegram user ID is invalid")
    return {"user": user, "user_id": user_id, "auth_date": auth_date}


def allowed_role(config, user_id):
    """Map the configured Telegram allow-list to the panel role."""
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return None
    admins = {int(value) for value in config.get("admins", []) if str(value).isdigit()}
    viewers = {int(value) for value in config.get("viewers", []) if str(value).isdigit()}
    if user_id in admins:
        return "admin"
    if user_id in viewers:
        return "viewer"
    if not admins and not viewers and str(config.get("chat_id", "")).isdigit() and int(config["chat_id"]) == user_id:
        return "viewer"
    return None
