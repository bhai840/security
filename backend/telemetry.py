import logging
import os
from pathlib import Path

from fastapi import FastAPI
from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

logger = logging.getLogger(__name__)
_provider: TracerProvider | None = None

load_dotenv(dotenv_path=Path(__file__).with_name(".env"))


def get_tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)


def configure_telemetry(app: FastAPI) -> None:
    global _provider

    if os.getenv("OTEL_ENABLED", "true").lower() in {"false", "0", "no"}:
        logger.info("OpenTelemetry tracing is disabled")
        return

    service_name = os.getenv("OTEL_SERVICE_NAME", "phishing-backend")
    resource_attributes = {"service.name": service_name}
    galileo_enabled = os.getenv("OTEL_GALILEO_ENABLED", "false").lower() in {
        "true",
        "1",
        "yes",
    }
    galileo_project = None
    galileo_log_stream = None

    if galileo_enabled:
        if not os.getenv("GALILEO_API_KEY"):
            raise RuntimeError(
                "OTEL_GALILEO_ENABLED is true, but GALILEO_API_KEY is not set"
            )
        galileo_project = os.getenv("GALILEO_PROJECT")
        if not galileo_project:
            raise RuntimeError(
                "OTEL_GALILEO_ENABLED is true, but GALILEO_PROJECT is not set"
            )
        galileo_log_stream = os.getenv("GALILEO_LOG_STREAM", "default")
        resource_attributes.update(
            {
                "galileo.project.name": galileo_project,
                "galileo.logstream.name": galileo_log_stream,
            }
        )

    _provider = TracerProvider(resource=Resource.create(resource_attributes))
    _provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

    if galileo_enabled:
        galileo_api_key = os.environ["GALILEO_API_KEY"]
        galileo_endpoint = os.getenv(
            "GALILEO_OTEL_ENDPOINT",
            "https://api.galileo.ai/otel/traces",
        )
        _provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(
                    endpoint=galileo_endpoint,
                    headers={
                        "Galileo-API-Key": galileo_api_key,
                        "project": galileo_project,
                        "logstream": galileo_log_stream,
                    },
                )
            )
        )
        logger.info(
            "OpenTelemetry traces will also be exported to Galileo project %s",
            galileo_project,
        )

    trace.set_tracer_provider(_provider)
    FastAPIInstrumentor.instrument_app(app)
    logger.info("OpenTelemetry tracing enabled for service %s", service_name)


def shutdown_telemetry() -> None:
    if _provider is not None:
        _provider.shutdown()
