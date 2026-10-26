import unittest
from unittest.mock import patch

from fastapi import FastAPI

import telemetry


class TelemetryTests(unittest.TestCase):
    @patch("telemetry.FastAPIInstrumentor.instrument_app")
    @patch("telemetry.trace.set_tracer_provider")
    @patch("telemetry.BatchSpanProcessor")
    @patch("telemetry.OTLPSpanExporter")
    @patch("telemetry.TracerProvider")
    @patch.dict(
        "os.environ",
        {
            "OTEL_ENABLED": "true",
            "OTEL_GALILEO_ENABLED": "true",
            "GALILEO_API_KEY": "test-api-key",
            "GALILEO_PROJECT": "test-project",
        },
        clear=True,
    )
    def test_galileo_and_splunk_processors_are_configured_together(
        self,
        provider_class,
        _otlp_exporter,
        _batch_processor,
        set_tracer_provider,
        instrument_app,
    ):
        provider = provider_class.return_value

        telemetry.configure_telemetry(FastAPI())

        self.assertEqual(_otlp_exporter.call_count, 2)
        _otlp_exporter.assert_any_call()
        _otlp_exporter.assert_any_call(
            endpoint="https://api.galileo.ai/otel/traces",
            headers={
                "Galileo-API-Key": "test-api-key",
                "project": "test-project",
                "logstream": "default",
            },
        )
        self.assertEqual(_batch_processor.call_count, 2)
        self.assertEqual(provider.add_span_processor.call_count, 2)
        resource = provider_class.call_args.kwargs["resource"]
        self.assertEqual(
            resource.attributes["galileo.project.name"],
            "test-project",
        )
        self.assertEqual(
            resource.attributes["galileo.logstream.name"],
            "default",
        )
        set_tracer_provider.assert_called_once_with(provider)
        instrument_app.assert_called_once()


if __name__ == "__main__":
    unittest.main()
