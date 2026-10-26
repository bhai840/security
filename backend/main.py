import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from gmail_client import (
    complete_google_oauth,
    fetch_recent_emails,
    is_gmail_connected,
    start_google_oauth,
)
from openrouter_client import classify_email
from soar import simulate_actions
from splunk_client import send_phishing_email_to_splunk
from telemetry import configure_telemetry, get_tracer, shutdown_telemetry


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    shutdown_telemetry()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

configure_telemetry(app)
tracer = get_tracer(__name__)

INCIDENTS = []  # in-memory for PoC


def _include_email_content_in_telemetry() -> bool:
    return os.getenv("SPLUNK_INCLUDE_EMAIL_CONTENT", "false").lower() in {
        "true",
        "1",
        "yes",
    }


def _export_phishing_email(email, result):
    if (
        not _include_email_content_in_telemetry()
        or not result["classification"].startswith("PHISHING_")
    ):
        return
    send_phishing_email_to_splunk(
        email,
        result["classification"],
        result["reason"],
    )


@app.get("/api/incidents")
def list_incidents():
    return INCIDENTS


@app.get("/api/auth/google/status")
def google_auth_status():
    return {"connected": is_gmail_connected()}


@app.get("/api/auth/google")
def google_auth_start():
    return start_google_oauth()


@app.get("/api/auth/google/callback")
def google_auth_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    return complete_google_oauth(code, state, error)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/scan")
def scan_inbox():
    with tracer.start_as_current_span("phishing.scan_inbox") as span:
        emails = fetch_recent_emails(limit=10)
        global INCIDENTS
        INCIDENTS = []

        for email in emails:
            with tracer.start_as_current_span("phishing.classify_email"):
                result = classify_email(email["subject"], email["body_preview"])
                incident = {
                    "id": email["id"],
                    "subject": email["subject"],
                    "from": email["from"],
                    "body_preview": email["body_preview"],
                    "classification": result["classification"],
                    "reason": result["reason"],
                    "actions_taken": [],
                }
                _export_phishing_email(email, result)
                simulate_actions(incident)
                INCIDENTS.append(incident)

        span.set_attribute("phishing.email_count", len(emails))
        span.set_attribute("phishing.incident_count", len(INCIDENTS))
        return {"count": len(INCIDENTS), "incidents": INCIDENTS}