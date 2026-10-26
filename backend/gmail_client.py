import base64
import logging
import os
import secrets
import time
from email.header import decode_header, make_header
from email.utils import parseaddr
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from fastapi import HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from opentelemetry import trace

load_dotenv()

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API_URL = "https://gmail.googleapis.com/gmail/v1"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
tracer = trace.get_tracer(__name__)
logger = logging.getLogger(__name__)

_oauth_states: dict[str, float] = {}
_oauth_tokens: dict[str, str | float] = {}


def _required_setting(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _oauth_settings() -> tuple[str, str, str]:
    return (
        _required_setting("GOOGLE_CLIENT_ID"),
        _required_setting("GOOGLE_CLIENT_SECRET"),
        _required_setting("GOOGLE_REDIRECT_URI"),
    )


def is_gmail_connected() -> bool:
    return bool(_oauth_tokens.get("refresh_token"))


def start_google_oauth() -> RedirectResponse:
    client_id, _, redirect_uri = _oauth_settings()
    now = time.monotonic()
    for expired_state, expires_at in list(_oauth_states.items()):
        if expires_at < now:
            del _oauth_states[expired_state]
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = now + 600
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": GMAIL_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
    )
    return RedirectResponse(f"{GOOGLE_AUTH_URL}?{query}")


def complete_google_oauth(code: str | None, state: str | None, error: str | None):
    if error:
        raise HTTPException(status_code=400, detail="Google authorization was denied")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing OAuth callback parameters")
    expires_at = _oauth_states.pop(state, None)
    if expires_at is None or expires_at < time.monotonic():
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    client_id, client_secret, redirect_uri = _oauth_settings()
    try:
        response = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=30,
        )
        response.raise_for_status()
        token_data = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(
            status_code=502, detail="Google token exchange failed"
        ) from exc

    refresh_token = token_data.get("refresh_token")
    access_token = token_data.get("access_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise HTTPException(
            status_code=502,
            detail="Google did not return a refresh token; reconnect and grant access",
        )
    if not isinstance(access_token, str) or not access_token:
        raise HTTPException(
            status_code=502, detail="Google did not return an access token"
        )

    _oauth_tokens["refresh_token"] = refresh_token
    _oauth_tokens["access_token"] = access_token
    _oauth_tokens["expires_at"] = time.time() + int(token_data.get("expires_in", 3600))
    return HTMLResponse(
        "<!doctype html><title>Gmail connected</title>"
        "<h1>Gmail connected</h1>"
        "<p>You can close this tab and return to the phishing detection app.</p>"
        '<p><a href="/">Return to the app</a></p>'
    )


def _get_access_token() -> str:
    if not is_gmail_connected():
        raise HTTPException(
            status_code=401, detail="Connect a Gmail account before scanning"
        )
    access_token = _oauth_tokens.get("access_token")
    expires_at = _oauth_tokens.get("expires_at", 0)
    if isinstance(access_token, str) and float(expires_at) > time.time() + 60:
        return access_token

    client_id, client_secret, _ = _oauth_settings()
    try:
        response = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": _oauth_tokens["refresh_token"],
                "grant_type": "refresh_token",
            },
            timeout=30,
        )
        response.raise_for_status()
        token_data = response.json()
    except requests.RequestException as exc:
        status = exc.response.status_code if exc.response is not None else None
        logger.warning("Google token refresh failed (HTTP %s)", status or "network error")
        raise HTTPException(
            status_code=502,
            detail=f"Google token refresh failed{f' (HTTP {status})' if status else ''}",
        ) from exc
    except ValueError as exc:
        logger.warning("Google token refresh returned invalid JSON")
        raise HTTPException(status_code=502, detail="Google token refresh returned invalid data") from exc

    access_token = token_data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise HTTPException(status_code=502, detail="Google returned no access token")
    _oauth_tokens["access_token"] = access_token
    _oauth_tokens["expires_at"] = time.time() + int(token_data.get("expires_in", 3600))
    return access_token


def _decode_body(data: str) -> str:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")


def _plain_text_parts(payload: dict) -> list[str]:
    parts = []
    if payload.get("mimeType") == "text/plain" and payload.get("body", {}).get("data"):
        parts.append(_decode_body(payload["body"]["data"]))
    for part in payload.get("parts", []):
        parts.extend(_plain_text_parts(part))
    return parts


def _decoded_header(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except (LookupError, UnicodeError, ValueError):
        return value


def fetch_recent_emails(limit: int = 10) -> list[dict[str, str]]:
    token = _get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    with tracer.start_as_current_span("gmail.fetch_recent_emails") as span:
        try:
            response = requests.get(
                f"{GMAIL_API_URL}/users/me/messages",
                headers=headers,
                params={"labelIds": "INBOX", "maxResults": limit},
                timeout=30,
            )
            response.raise_for_status()
            messages = response.json().get("messages", [])
            emails = []
            for message in messages:
                message_response = requests.get(
                    f"{GMAIL_API_URL}/users/me/messages/{message['id']}",
                    headers=headers,
                    params={"format": "full"},
                    timeout=30,
                )
                message_response.raise_for_status()
                item = message_response.json()
                payload = item.get("payload", {})
                message_headers = {
                    header.get("name", "").lower(): header.get("value", "")
                    for header in payload.get("headers", [])
                }
                body = "\n".join(_plain_text_parts(payload)) or item.get("snippet", "")
                emails.append(
                    {
                        "id": item.get("id", message["id"]),
                        "subject": _decoded_header(message_headers.get("subject", "")),
                        "from": parseaddr(message_headers.get("from", ""))[1],
                        "body": body,
                        "body_preview": body[:4000],
                    }
                )
        except requests.RequestException as exc:
            span.set_attribute("error.type", type(exc).__name__)
            span.set_status(trace.Status(trace.StatusCode.ERROR))
            status = exc.response.status_code if exc.response is not None else None
            logger.warning("Gmail API request failed (HTTP %s)", status or "network error")
            raise HTTPException(
                status_code=502,
                detail=f"Gmail API request failed{f' (HTTP {status})' if status else ''}",
            ) from exc
        except (ValueError, KeyError) as exc:
            span.set_attribute("error.type", type(exc).__name__)
            span.set_status(trace.Status(trace.StatusCode.ERROR))
            logger.warning("Gmail API returned an invalid message response")
            raise HTTPException(
                status_code=502, detail="Gmail API returned an invalid response"
            ) from exc

        span.set_attribute("phishing.email_count", len(emails))
        return emails
