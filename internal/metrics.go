package internal

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars"
	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// OpenTelemetry metrics (design §19.5), exported over OTLP/HTTP when an
// OTLP endpoint is configured in the environment, like the audit records.

const metricsScope = "github.com/Tracefort-io/opa-authzen-plugin"

// metricAuthFailures is shared with the service's instrument of that name.
const metricAuthFailures = ars.MetricAuthFailures

// counters and histograms of ars.Metrics, with their descriptions.
var (
	counterNames = map[string]string{
		ars.MetricSubmissions:        "Access request submissions, by outcome.",
		ars.MetricDecisions:          "Approver decisions.",
		ars.MetricTransitions:        "Tasks reaching a terminal status.",
		ars.MetricApprovalLookups:    "Approvals resolved at re-evaluation, by result.",
		ars.MetricDBErrors:           "Store errors, by operation.",
		ars.MetricAuthFailures:       "Rejected credentials, by API and reason.",
		ars.MetricCallbackDeliveries: "Callback delivery attempts, by outcome.",
	}
	histogramNames = map[string]string{
		ars.MetricSweepLag:        "Seconds from a task's expiry to the sweep that expired it.",
		ars.MetricCallbackLatency: "Seconds from a task's completion to its callback's delivery.",
	}
)

// otelMetrics implements ars.Metrics with OpenTelemetry instruments.
type otelMetrics struct {
	counters   map[string]metric.Int64Counter
	histograms map[string]metric.Float64Histogram
	shutdown   func(context.Context) error
}

// newOTelMetrics returns metrics exporting over OTLP/HTTP when an OTLP
// endpoint is configured, and nil otherwise. backlog, when it returns a
// store, feeds the pending-task and callback-backlog gauges.
func newOTelMetrics(ctx context.Context, backlog func() store.Store) (*otelMetrics, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") == "" {
		return nil, nil
	}
	exp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("OTLP metric exporter: %w", err)
	}
	return newMetricsWithReader(ctx, sdkmetric.NewPeriodicReader(exp), backlog)
}

func newMetricsWithReader(ctx context.Context, reader sdkmetric.Reader, backlog func() store.Store) (*otelMetrics, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", defaultService)),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, fmt.Errorf("OTel resource: %w", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res))
	meter := provider.Meter(metricsScope)
	m := &otelMetrics{counters: map[string]metric.Int64Counter{}, histograms: map[string]metric.Float64Histogram{}, shutdown: provider.Shutdown}
	for name, desc := range counterNames {
		if m.counters[name], err = meter.Int64Counter(name, metric.WithDescription(desc)); err != nil {
			return nil, err
		}
	}
	for name, desc := range histogramNames {
		if m.histograms[name], err = meter.Float64Histogram(name, metric.WithDescription(desc), metric.WithUnit("s")); err != nil {
			return nil, err
		}
	}
	pending, err := meter.Int64ObservableGauge(ars.MetricPendingTasks, metric.WithDescription("Pending access request tasks, across all replicas."))
	if err != nil {
		return nil, err
	}
	undelivered, err := meter.Int64ObservableGauge(ars.MetricCallbackBacklog, metric.WithDescription("Callback notifications not yet delivered, across all replicas."))
	if err != nil {
		return nil, err
	}
	if _, err := meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		st := backlog()
		if st == nil {
			return nil
		}
		p, u, err := st.Backlog(ctx)
		if err != nil {
			m.Count(ctx, ars.MetricDBErrors, map[string]string{"operation": "backlog"})
			return nil
		}
		o.ObserveInt64(pending, p)
		o.ObserveInt64(undelivered, u)
		return nil
	}, pending, undelivered); err != nil {
		return nil, err
	}
	return m, nil
}

func attrs(m map[string]string) metric.MeasurementOption {
	kv := make([]attribute.KeyValue, 0, len(m))
	for k, v := range m {
		kv = append(kv, attribute.String(k, v))
	}
	return metric.WithAttributes(kv...)
}

// Count implements ars.Metrics.
func (m *otelMetrics) Count(ctx context.Context, name string, a map[string]string) {
	if c, ok := m.counters[name]; ok {
		c.Add(ctx, 1, attrs(a))
	}
}

// Observe implements ars.Metrics.
func (m *otelMetrics) Observe(ctx context.Context, name string, v float64, a map[string]string) {
	if h, ok := m.histograms[name]; ok {
		h.Record(ctx, v, attrs(a))
	}
}

// Shutdown flushes and stops the exporter.
func (m *otelMetrics) Shutdown(ctx context.Context) error {
	if m == nil || m.shutdown == nil {
		return nil
	}
	return m.shutdown(ctx)
}

// pluginMetrics is the plugin's ars.Metrics: OpenTelemetry once started
// with an OTLP endpoint, discarding measurements otherwise.
type pluginMetrics struct {
	mu sync.RWMutex
	m  ars.Metrics
}

func (p *pluginMetrics) set(m ars.Metrics) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m = m
}

func (p *pluginMetrics) get() ars.Metrics {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.m
}

// Count implements ars.Metrics.
func (p *pluginMetrics) Count(ctx context.Context, name string, a map[string]string) {
	if m := p.get(); m != nil {
		m.Count(ctx, name, a)
	}
}

// Observe implements ars.Metrics.
func (p *pluginMetrics) Observe(ctx context.Context, name string, v float64, a map[string]string) {
	if m := p.get(); m != nil {
		m.Observe(ctx, name, v, a)
	}
}
