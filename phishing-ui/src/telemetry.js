import { trace, SpanStatusCode } from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { WebTracerProvider } from "@opentelemetry/sdk-trace-web";

const endpoint =
  process.env.REACT_APP_OTEL_EXPORTER_OTLP_ENDPOINT ||
  "/otel/v1/traces";

const provider = new WebTracerProvider({
  resource: resourceFromAttributes({ "service.name": "phishing-ui" }),
  spanProcessors: [
    new BatchSpanProcessor(new OTLPTraceExporter({ url: endpoint })),
  ],
});
provider.register();

const tracer = trace.getTracer("phishing-ui");

export function withApiSpan(name, operation) {
  return tracer.startActiveSpan(name, async (span) => {
    const spanContext = span.spanContext();
    const headers = {
      traceparent: `00-${spanContext.traceId}-${spanContext.spanId}-${spanContext.traceFlags
        .toString(16)
        .padStart(2, "0")}`,
    };

    try {
      return await operation(headers);
    } catch (error) {
      span.recordException(error);
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message,
      });
      throw error;
    } finally {
      span.end();
    }
  });
}
