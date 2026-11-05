package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

// The Access Request Service's audit trail is a stream of OpenTelemetry log
// records, one per state change, emitted after the change commits. Where
// they go, and how long they are kept, is the OpenTelemetry pipeline's
// concern: the exporter is configured by the standard OTEL_EXPORTER_OTLP_*
// variables, and the database keeps no audit history of its own.

const (
	auditScope       = "github.com/Tracefort-io/opa-authzen-plugin/ars"
	auditEventPrefix = "authzen.access_request."
	defaultService   = "opa-authzen-plugin"
)

// otelAuditor emits audit records through an OpenTelemetry logger.
type otelAuditor struct {
	logger   otellog.Logger
	shutdown func(context.Context) error
	now      func() time.Time
}

// newOTelAuditor builds an auditor exporting over OTLP/HTTP when an OTLP
// endpoint is configured in the environment, and returns nil otherwise.
func newOTelAuditor(ctx context.Context) (*otelAuditor, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") == "" {
		return nil, nil
	}
	exp, err := otlploghttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("OTLP log exporter: %w", err)
	}
	// Later options win, so OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES
	// override the default service name.
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", defaultService)),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, fmt.Errorf("OTel resource: %w", err)
	}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
		sdklog.WithResource(res),
	)
	return &otelAuditor{logger: provider.Logger(auditScope), shutdown: provider.Shutdown, now: time.Now}, nil
}

// Emit implements ars.Auditor.
func (a *otelAuditor) Emit(ctx context.Context, event string, attrs map[string]any) {
	var r otellog.Record
	now := a.now()
	r.SetTimestamp(now)
	r.SetObservedTimestamp(now)
	r.SetEventName(auditEventPrefix + event)
	r.SetSeverity(otellog.SeverityInfo)
	r.SetSeverityText("INFO")
	r.SetBody(attribute.StringValue(event))
	r.AddAttributes(auditAttributes(attrs)...)
	a.logger.Emit(ctx, r)
}

// Shutdown flushes buffered records.
func (a *otelAuditor) Shutdown(ctx context.Context) error {
	if a == nil || a.shutdown == nil {
		return nil
	}
	return a.shutdown(ctx)
}

// auditAttributes renders an audit record's attributes, prefixed with
// "authzen.". Strings stay strings; structured values (subjects,
// resources, actions) are JSON-encoded so every backend can store them.
func auditAttributes(attrs map[string]any) []attribute.KeyValue {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]attribute.KeyValue, 0, len(keys))
	for _, k := range keys {
		name := "authzen." + k
		switch v := attrs[k].(type) {
		case nil:
		case string:
			if v != "" {
				out = append(out, attribute.String(name, v))
			}
		case bool:
			out = append(out, attribute.Bool(name, v))
		default:
			b, err := json.Marshal(v)
			if err == nil {
				out = append(out, attribute.String(name, string(b)))
			}
		}
	}
	return out
}
