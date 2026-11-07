package ars

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

// outcomeRecorder notes a response's status and problem type, so a
// handler's outcome is counted once whichever way it answered.
type outcomeRecorder struct {
	http.ResponseWriter
	status  int
	problem string
}

func (o *outcomeRecorder) WriteHeader(code int) {
	o.status = code
	o.ResponseWriter.WriteHeader(code)
}

func (o *outcomeRecorder) Write(b []byte) (int, error) {
	if o.status == 0 {
		o.status = http.StatusOK
	}
	if o.status >= 400 && o.problem == "" {
		var p struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(b, &p)
		o.problem = strings.TrimPrefix(p.Type, problemPrefix)
		if o.problem == "" || o.problem == problemGeneric {
			o.problem = "status_" + strconv.Itoa(o.status)
		}
	}
	return o.ResponseWriter.Write(b)
}

// countSubmission records a submission's outcome: pending (202),
// auto_decided (201) or rejected, with its problem type.
func (s *Service) countSubmission(ctx context.Context, o *outcomeRecorder) {
	switch o.status {
	case http.StatusAccepted:
		s.d.Metrics.Count(ctx, MetricSubmissions, map[string]string{"outcome": "pending"})
	case http.StatusCreated:
		s.d.Metrics.Count(ctx, MetricSubmissions, map[string]string{"outcome": "auto_decided"})
	default:
		s.d.Metrics.Count(ctx, MetricSubmissions, map[string]string{"outcome": "rejected", "problem": o.problem})
	}
}

// completed counts a task reaching a terminal status.
func (s *Service) completed(ctx context.Context, t *store.Task) {
	s.d.Metrics.Count(ctx, MetricTransitions, map[string]string{"status": t.Status})
}

func seconds(d time.Duration) float64 { return d.Seconds() }

// Metrics receives the service's measurements (design §19.5). The plugin
// backs it with OpenTelemetry; the zero Deps value discards them.
type Metrics interface {
	// Count adds one to a counter.
	Count(ctx context.Context, name string, attrs map[string]string)
	// Observe records a value in a histogram.
	Observe(ctx context.Context, name string, value float64, attrs map[string]string)
}

// Instrument names.
const (
	MetricSubmissions        = "authzen.ars.submissions"
	MetricDecisions          = "authzen.ars.decisions"
	MetricTransitions        = "authzen.ars.transitions"
	MetricApprovalLookups    = "authzen.ars.approval_lookups"
	MetricDBErrors           = "authzen.ars.db_errors"
	MetricAuthFailures       = "authzen.ars.auth_failures"
	MetricSweepLag           = "authzen.ars.sweep_lag"
	MetricCallbackDeliveries = "authzen.ars.callback_deliveries"
	MetricCallbackLatency    = "authzen.ars.callback_latency"
	MetricPendingTasks       = "authzen.ars.pending_tasks"
	MetricCallbackBacklog    = "authzen.ars.callback_backlog"
)

type noMetrics struct{}

func (noMetrics) Count(context.Context, string, map[string]string)            {}
func (noMetrics) Observe(context.Context, string, float64, map[string]string) {}
