package internal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// captureExporter keeps every exported record.
type captureExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *captureExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range records {
		e.records = append(e.records, records[i].Clone())
	}
	return nil
}
func (*captureExporter) Shutdown(context.Context) error   { return nil }
func (*captureExporter) ForceFlush(context.Context) error { return nil }

func TestOTelAuditorRecord(t *testing.T) {
	exp := &captureExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))
	a := &otelAuditor{logger: provider.Logger(auditScope), shutdown: provider.Shutdown, now: func() time.Time { return time.Unix(1790000000, 0) }}

	a.Emit(context.Background(), "decided", map[string]any{
		"task_id":  "arq_1",
		"actor":    "https://idp.example.com|manager",
		"decision": "approve",
		"subject":  map[string]any{"type": "user", "id": "bob"},
		"comment":  "",
	})
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(exp.records) != 1 {
		t.Fatalf("expected one record, got %d", len(exp.records))
	}
	r := exp.records[0]
	if r.EventName() != "authzen.access_request.decided" || r.Body().AsString() != "decided" || !r.Timestamp().Equal(time.Unix(1790000000, 0)) {
		t.Fatalf("record: event=%q body=%q ts=%v", r.EventName(), r.Body().AsString(), r.Timestamp())
	}
	got := map[string]string{}
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		got[string(kv.Key)] = kv.Value.String()
		return true
	})
	want := map[string]string{
		"authzen.task_id":  "arq_1",
		"authzen.actor":    "https://idp.example.com|manager",
		"authzen.decision": "approve",
		"authzen.subject":  `{"id":"bob","type":"user"}`,
	}
	if len(got) != len(want) {
		t.Fatalf("attributes %v, want %v (empty strings dropped)", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("attribute %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestOTelAuditorDisabledWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	a, err := newOTelAuditor(context.Background())
	if err != nil || a != nil {
		t.Fatalf("expected no auditor without an endpoint, got %v %v", a, err)
	}
}

// TestOTelAuditorExportsOverOTLP sends a record to a local OTLP/HTTP
// receiver configured through the standard environment variable.
func TestOTelAuditorExportsOverOTLP(t *testing.T) {
	var hits atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/logs" && r.Method == http.MethodPost {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", receiver.URL+"/v1/logs")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	a, err := newOTelAuditor(context.Background())
	if err != nil || a == nil {
		t.Fatalf("auditor: %v %v", a, err)
	}
	a.Emit(context.Background(), "submitted", map[string]any{"task_id": "arq_1"})
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits.Load() == 0 {
		t.Fatal("no OTLP export reached the receiver")
	}
}
