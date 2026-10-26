# Phishing detection demo: observability and evaluation

## Summary

- The FastAPI backend and React UI emit OpenTelemetry traces through a local
  OpenTelemetry Collector.
- The Collector exports traces, metrics, and logs to Splunk through the HTTP
  Event Collector (HEC).
- The backend can additionally export traces directly to Galileo using its
  OpenTelemetry span processor.
- The Galileo evaluation script runs the classifier against labeled synthetic
  examples, reports exact-match metrics locally, and can optionally submit a
  Galileo experiment scored with ground-truth adherence.
- Email content is excluded from telemetry by default. Set
  `SPLUNK_INCLUDE_EMAIL_CONTENT=true` only when you have approval to send
  detected phishing messages to Splunk; this includes sender, subject, body,
  classification, and reason. Gmail's plain-text body is used, with its snippet
  as a fallback; attachments are not included.

## Docker Compose deployment

The production Compose stack builds the React frontend and FastAPI backend as
separate images and runs the OpenTelemetry Collector alongside them. The
Collector sends telemetry to Splunk through the HTTP Event Collector (HEC).
The UI is served on port `8080` by default; its Nginx proxy sends `/api/`
requests to the backend and `/otel/v1/traces` requests to the Collector. This
keeps browser traffic same-origin and avoids exposing container-only hostnames
to browsers.

On the Linux host, prepare the two environment files:

```sh
cp .env.example .env
cp backend/.env.example backend/.env
```

Set the Splunk HEC URL, token, and index in the root `.env`. Set the Microsoft
Graph and OpenRouter credentials in `backend/.env`, plus Galileo settings if
Galileo trace export is enabled. Compose injects the backend file at runtime;
the Docker build context excludes local environment files and virtual
environments. Do not commit either file.

Build and start the stack:

```sh
docker compose up --build -d
docker compose ps
```

Open `http://<linux-host>:8080` and run a scan. Change `FRONTEND_PORT` in the
root `.env` if port `8080` is unavailable. For an internet-facing deployment,
put the frontend behind a TLS-terminating reverse proxy or load balancer.

The browser and backend use the distinct OpenTelemetry service names
`phishing-ui` and `phishing-backend`; their telemetry is sent to the configured
Splunk HEC index. The backend exports to `otel-collector:4318` on the Compose
network, while the browser sends telemetry to the frontend's same-origin proxy.
The backend health endpoint is available internally at `/health`.

To inspect startup and export errors or stop the stack:

```sh
docker compose logs -f frontend backend otel-collector
docker compose down
```

## Step-by-step setup

### 1. Prerequisites

- Python 3.10 or newer
- Node.js and npm
- Docker Compose v2
- A Google Cloud project with the Gmail API enabled and a Web application OAuth
  client
- An OpenRouter API key
- A Splunk HEC token and index

### 2. Configure and start the OpenTelemetry Collector

From the project root, copy the template and fill in the credentials and
endpoints for your Splunk instances:

```powershell
Copy-Item .env.example .env
```

Create or obtain an HTTP Event Collector (HEC) token in Splunk, then set
`SPLUNK_HEC_URL` to your Splunk HEC endpoint ending in `/services/collector`,
and set the token and destination index. Splunk Cloud HEC endpoints are
provided by your Splunk Cloud instance. The Universal Forwarder package is not
needed for this collector-to-Splunk connection.

Start the Collector:

```powershell
docker compose -f docker-compose.otel.yml up -d
```

The Collector listens on OTLP/gRPC port `4317` and OTLP/HTTP port `4318`.
Browser OTLP/HTTP requests are allowed from `http://localhost:3000`; update
`otel-collector-config.yaml` if the UI uses another origin.

### 3. Configure and start the backend

Copy the backend environment template and configure the Google OAuth and
OpenRouter values:

```powershell
Copy-Item backend\.env.example backend\.env
```

In Google Cloud Console, enable the Gmail API, configure the OAuth consent
screen, and add your Gmail account as a test user. Add this exact Authorized
redirect URI to the Web application OAuth client:

```text
http://localhost:8080/api/auth/google/callback
```

Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` in
`backend\.env`. Set the redirect URI to the same value above. The application
requests Gmail read-only access. Do not paste OAuth client secrets or tokens
into chat or commit them to source control.

To also export scanned message details to Splunk, set
`SPLUNK_INCLUDE_EMAIL_CONTENT=true` in `backend\.env` after confirming that your
mailbox users and organization's data-handling policies permit it. For messages
classified as phishing, the scan exports the message ID, sender, subject, full
plain-text body, classification, and reason as a separate event directly to
Splunk HEC (`source=phishing-email`). This is not attached to OpenTelemetry
traces, so Galileo does not receive the email content. This setting defaults to
`false`; attachments are not exported. The classifier still receives only the
existing 4,000-character body preview. Splunk retention and access controls
will apply to the full body sent in the event.

Start or rebuild the stack, then open `http://localhost:8080`, choose
**Connect Gmail**, sign in to the test account, and grant read-only access.
Return to the app and choose **Scan Gmail Inbox**. OAuth tokens are held in
backend memory and are not persisted; reconnect after restarting the backend.
OAuth apps left in Google's Testing publishing status may have refresh tokens
that expire after seven days.

After a scan, find phishing email events in Splunk with:

```spl
index=<value of SPLUNK_HEC_INDEX> source=phishing-email
```

For a standalone backend development run (instead of Docker):

```powershell
py -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Set-Location backend
uvicorn main:app --reload --no-access-log
```

`OTEL_EXPORTER_OTLP_ENDPOINT` defaults to `http://localhost:4318`. Set
`OTEL_ENABLED=false` in `backend\.env` to disable backend tracing. Startup and
export errors are reported by the OpenTelemetry SDK/Collector; requests to the
model or Graph API still fail visibly if their credentials or services are
unavailable.

To export backend traces to Galileo, set `OTEL_GALILEO_ENABLED=true`,
`GALILEO_API_KEY`, `GALILEO_PROJECT`, and optionally `GALILEO_LOG_STREAM` and
`GALILEO_OTEL_ENDPOINT` in `backend\.env`. Use
`OTEL_GALILEO_ENABLED=false` to keep Galileo for the explicit model-evaluation
workflow only. The Galileo endpoint defaults to
`https://api.galileo.ai/otel/traces`. The Galileo API key is
separate from the OpenRouter key. The default trace export includes operation
names, model name, classification, and counts, but not email text or the model's
reason. Keep prompt/response content out of telemetry unless its upload has
been explicitly approved.

### 4. Configure and start the UI for local development

In a second PowerShell window:

```powershell
Copy-Item phishing-ui\.env.example phishing-ui\.env.development.local
Set-Location phishing-ui
npm ci
npm start
```

The development UI runs on `http://localhost:3000`. The production Compose UI
runs on `http://localhost:8080`. The UI sends its spans to the Collector's
OTLP/HTTP endpoint and propagates W3C `traceparent` headers to the backend,
linking UI requests with backend traces.

### 5. Verify telemetry in Splunk

Open the UI at `http://localhost:8080`, connect the test Gmail account, then
select **Scan Gmail Inbox**.
Allow a few seconds for the Collector's batch processor to export spans.

- In Splunk, search the configured HEC index for events with
  `source=phishing-otel`.
- Backend spans include `phishing.scan_inbox`, `gmail.fetch_recent_emails`, and
  `openrouter.classify_email`.

### 6. Run the classifier evaluation

From the backend directory, run the local evaluation against the included
synthetic labeled examples:

```powershell
python galileo_eval.py
```

It runs the configured OpenRouter model and prints accuracy, macro F1, per-class
precision/recall/F1, and a confusion matrix. To also publish the results to
Galileo, set `GALILEO_API_KEY` and `GALILEO_PROJECT` in `backend\.env`, then
explicitly opt in:

```powershell
python galileo_eval.py --publish-to-galileo
```

The script creates a Galileo dataset from the evaluated inputs, model labels,
and expected labels, then runs an experiment with
`GalileoMetrics.ground_truth_adherence`. Configure an LLM integration in the
Galileo project if the selected metric requires one. Only publish data that is
approved for the Galileo account; the checked-in evaluation cases are synthetic.
You can use `--cases path\to\cases.json` to evaluate another labeled JSON array
with `subject`, `body`, and `expected_classification` fields.

To have Galileo run the model itself instead of uploading predictions generated
locally, configure an OpenRouter custom model integration in Galileo under
**Settings > Integrations**. Use `https://openrouter.ai/api/v1` as the endpoint,
`Authorization` as the API key header, and `Bearer <OpenRouter API key>` as its
value. Register the configured OpenRouter model ID as a model and set its alias
to the same value as `GALILEO_MODEL_ALIAS` in `backend\.env`. Then run:

```json
{
  "authentication_type": "api_key",
  "api_key_header": "Authorization",
  "api_key_value": "Bearer <OpenRouter API key>",
  "endpoint": "https://openrouter.ai/api/v1",
  "model_properties": [
    {
      "name": "nvidia/nemotron-3-ultra-550b-a55b:free",
      "alias": "OpenRouter Nemotron Free",
      "supported_parameters": ["max_tokens", "temperature", "top_p"]
    }
  ]
}
```

Set `GALILEO_MODEL_ALIAS=OpenRouter Nemotron Free` in `backend\.env` (or use
the alias you configured in Galileo).

Then run:

```powershell
python galileo_eval.py --run-in-galileo
```

This uploads the labeled synthetic inputs to Galileo; Galileo's experiment
runner calls the model through the configured OpenRouter integration and
evaluates the generated outputs. It does not send the OpenRouter key from the
backend `.env`. The model/provider integration and any metric judge integration
must be configured in Galileo. Do not combine `--run-in-galileo` with
`--publish-to-galileo`.

## Configuration notes

- Do not commit `.env` files, Splunk tokens, Google OAuth secrets, or API
  keys. The checked-in `.env.example` files contain placeholders only.
- The backend defaults to OpenRouter model
  `nvidia/nemotron-3-ultra-550b-a55b:free`. Set `OPENROUTER_MODEL` in
  `backend\.env` to override it.
- `splunk_hec` exports traces, metrics, and logs to the configured Splunk HEC
  index.
- Current application instrumentation emits traces. The Collector's HEC
  metrics/logs pipelines are ready for additional OTLP data sources.
- Galileo publishing is off by default. The evaluation sends email text to
  Galileo only when `--publish-to-galileo` is provided.
