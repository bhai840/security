import os
import logging
import time

import requests
from fastapi import HTTPException

logger = logging.getLogger(__name__)


def send_phishing_email_to_splunk(
    email: dict[str, str], classification: str, reason: str
) -> None:
    endpoint = os.getenv("SPLUNK_HEC_URL")
    token = os.getenv("SPLUNK_HEC_TOKEN")
    index = os.getenv("SPLUNK_HEC_INDEX")
    if not endpoint or not token or not index:
        raise HTTPException(
            status_code=503,
            detail="Splunk HEC is not configured for email-content export",
        )

    event = {
        "email_id": email["id"],
        "sender": email["from"],
        "subject": email["subject"],
        "body": email["body"],
        "classification": classification,
        "reason": reason,
    }
    payload = {
        "time": time.time(),
        "host": "phishing-backend",
        "source": "phishing-email",
        "sourcetype": "_json",
        "index": index,
        "event": event,
    }
    try:
        response = requests.post(
            endpoint,
            json=payload,
            headers={"Authorization": f"Splunk {token}"},
            timeout=15,
        )
        response.raise_for_status()
        result = response.json()
    except requests.RequestException as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status is None:
            logger.warning("Splunk HEC connection failed (%s)", type(exc).__name__)
            raise HTTPException(
                status_code=502,
                detail=(
                    "Cannot reach Splunk HEC; verify the endpoint hostname, "
                    "port, DNS, and network access"
                ),
            ) from exc
        raise HTTPException(
            status_code=502,
            detail=f"Splunk HEC export failed{f' (HTTP {status})' if status else ''}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=502, detail="Splunk HEC returned an invalid response"
        ) from exc

    if result.get("code") != 0:
        raise HTTPException(
            status_code=502,
            detail=f"Splunk HEC rejected the email event (code {result.get('code')})",
        )
