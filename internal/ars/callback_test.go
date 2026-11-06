package ars

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

var callbackSecret = []byte("0123456789abcdef0123456789abcdef")

// receiver is a PEP's callback endpoint.
type receiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	got    []receivedCallback
	status int
}

type receivedCallback struct {
	body      []byte
	signature string
	delivery  string
}

func newReceiver(t *testing.T) *receiver {
	rc := &receiver{status: http.StatusNoContent}
	rc.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		defer rc.mu.Unlock()
		rc.got = append(rc.got, receivedCallback{body: body, signature: r.Header.Get(SignatureHeader), delivery: r.Header.Get(DeliveryHeader)})
		w.WriteHeader(rc.status)
	}))
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *receiver) received() []receivedCallback {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]receivedCallback(nil), rc.got...)
}

// withCallbacks enables callbacks to the receiver, which listens on
// 127.0.0.1 and so needs allowInternal to be reached.
func (f *fixture) withCallbacks(rc *receiver, allowInternal bool) {
	roots := x509.NewCertPool()
	roots.AddCert(rc.srv.Certificate())
	cfg := &CallbackConfig{
		Timeout: 2 * time.Second, MaxAttempts: 2, RootCAs: roots,
		Destinations: map[string]CallbackDestination{
			"127.0.0.1": {Secret: callbackSecret, AllowInternal: allowInternal},
		},
	}
	f.svc.d.Callbacks = cfg
	f.svc.callbackClient = newCallbackClient(cfg)
}

func (f *fixture) submitWithCallback(t *testing.T, callback map[string]any, auto string) *httptest.ResponseRecorder {
	if auto != "" {
		f.rules["ars_workflow"] = func(map[string]any) any { return map[string]any{"auto": auto} }
	}
	body := f.submission(t, bindingClaims())
	body["callback"] = callback
	return f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), body)
}

func TestCallbackDelivered(t *testing.T) {
	f := newFixture(t)
	rc := newReceiver(t)
	f.withCallbacks(rc, true)
	w := f.submitWithCallback(t, map[string]any{"endpoint": rc.srv.URL + "/cb", "state": "session-1"}, "approve")
	if w.Code != http.StatusCreated {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	id := decode(t, w)["task"].(map[string]any)["id"].(string)
	f.svc.deliverDue(context.Background())

	got := rc.received()
	if len(got) != 1 {
		t.Fatalf("expected one callback, got %d", len(got))
	}
	var body map[string]any
	_ = json.Unmarshal(got[0].body, &body)
	task := body["task"].(map[string]any)
	if body["state"] != "session-1" || task["id"] != id || task["status"] != "approved" || task["status_endpoint"] != baseURL+RequestsPath+"/"+id {
		t.Fatalf("callback body: %s", got[0].body)
	}
	if _, has := body["result"]; has {
		t.Fatal("a callback carries a result")
	}
	// The receiver authenticates it by recomputing the signature.
	parts := strings.Split(got[0].signature, ",")
	ts := strings.TrimPrefix(parts[0], "t=")
	if len(parts) != 2 || parts[1] != "v1="+SignCallback(callbackSecret, ts, got[0].body) || got[0].delivery == "" {
		t.Fatalf("signature %q, delivery %q", got[0].signature, got[0].delivery)
	}
	if f.audit.events[len(f.audit.events)-1] != "callback_delivered" {
		t.Fatalf("audit: %v", f.audit.events)
	}
	// Delivered once only.
	f.svc.deliverDue(context.Background())
	if len(rc.received()) != 1 {
		t.Fatal("a delivered callback was sent again")
	}
}

func TestCallbackEventsFilter(t *testing.T) {
	f := newFixture(t)
	rc := newReceiver(t)
	f.withCallbacks(rc, true)
	if w := f.submitWithCallback(t, map[string]any{"endpoint": rc.srv.URL, "events": []any{"approved"}}, "deny"); w.Code != http.StatusCreated {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	f.svc.deliverDue(context.Background())
	if n := len(rc.received()); n != 0 {
		t.Fatalf("a callback for an event not asked for: %d", n)
	}
}

func TestCallbackOnApproverDecision(t *testing.T) {
	f := newFixture(t)
	rc := newReceiver(t)
	f.withCallbacks(rc, true)
	w := f.submitWithCallback(t, map[string]any{"endpoint": rc.srv.URL}, "")
	id := decode(t, w)["task"].(map[string]any)["id"].(string)
	f.svc.deliverDue(context.Background())
	if len(rc.received()) != 0 {
		t.Fatal("a pending task notified")
	}
	f.decide(t, id, "manager", map[string]any{"decision": "deny"})
	f.svc.deliverDue(context.Background())
	if got := rc.received(); len(got) != 1 || !strings.Contains(string(got[0].body), `"denied"`) {
		t.Fatalf("callbacks: %v", got)
	}
}

func TestCallbackRetriesThenFails(t *testing.T) {
	f := newFixture(t)
	rc := newReceiver(t)
	rc.status = http.StatusServiceUnavailable
	f.withCallbacks(rc, true)
	f.submitWithCallback(t, map[string]any{"endpoint": rc.srv.URL}, "approve")
	f.svc.deliverDue(context.Background())
	if len(rc.received()) != 1 {
		t.Fatal("first attempt not made")
	}
	// Not retried before its backoff.
	f.svc.deliverDue(context.Background())
	if len(rc.received()) != 1 {
		t.Fatal("retried before the backoff")
	}
	f.svc.d.Now = func() time.Time { return now.Add(time.Minute) }
	f.svc.deliverDue(context.Background())
	if len(rc.received()) != 2 || f.audit.events[len(f.audit.events)-1] != "callback_failed" {
		t.Fatalf("after max_attempts: %d attempts, audit %v", len(rc.received()), f.audit.events)
	}
	f.svc.d.Now = func() time.Time { return now.Add(time.Hour) }
	f.svc.deliverDue(context.Background())
	if len(rc.received()) != 2 {
		t.Fatal("a failed callback was sent again")
	}
}

// The address is checked again on the IP actually dialled: a destination
// not allowed internal addresses is never connected to one, whatever it
// resolved to at submission (the task here is stored directly, as if the
// submission check had passed before the host was rebound).
func TestCallbackRefusesInternalAddressAtDelivery(t *testing.T) {
	f := newFixture(t)
	rc := newReceiver(t)
	f.withCallbacks(rc, false)
	done := now
	task := &store.Task{
		ID: "arq_rebound", Status: store.StatusApproved, Subject: map[string]any{"type": "user", "id": "alice"},
		Denial: map[string]any{}, Callback: &store.Callback{Endpoint: rc.srv.URL},
		Items:     []store.Item{{Resource: map[string]any{}, Action: map[string]any{}, Status: store.StatusApproved}},
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, CompletedAt: &done,
	}
	if _, _, err := f.store.CreateTask(context.Background(), &store.NewTask{Task: task}, now); err != nil {
		t.Fatal(err)
	}
	f.svc.deliverDue(context.Background())
	if len(rc.received()) != 0 {
		t.Fatal("connected to an internal address")
	}
	f.svc.d.Now = func() time.Time { return now.Add(time.Minute) }
	f.svc.deliverDue(context.Background())
	if f.audit.events[len(f.audit.events)-1] != "callback_failed" {
		t.Fatalf("audit: %v", f.audit.events)
	}
}

func TestCallbackRejectedAtSubmission(t *testing.T) {
	f := newFixture(t)
	rc := newReceiver(t)
	cases := map[string]struct {
		enabled       bool
		allowInternal bool
		callback      any
	}{
		"callbacks not enabled":   {false, true, map[string]any{"endpoint": rc.srv.URL}},
		"not https":               {true, true, map[string]any{"endpoint": strings.Replace(rc.srv.URL, "https", "http", 1)}},
		"host not allowed":        {true, true, map[string]any{"endpoint": "https://other.example.com/cb"}},
		"internal address":        {true, false, map[string]any{"endpoint": rc.srv.URL}},
		"credentials in endpoint": {true, true, map[string]any{"endpoint": "https://u:p@127.0.0.1/cb"}},
		"unknown event":           {true, true, map[string]any{"endpoint": rc.srv.URL, "events": []any{"approved", "pending"}}},
		"empty events":            {true, true, map[string]any{"endpoint": rc.srv.URL, "events": []any{}}},
		"state too long":          {true, true, map[string]any{"endpoint": rc.srv.URL, "state": strings.Repeat("s", maxCallbackState+1)}},
		"not an object":           {true, true, "https://127.0.0.1/cb"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f.svc.d.Callbacks = nil
			if c.enabled {
				f.withCallbacks(rc, c.allowInternal)
			}
			body := f.submission(t, bindingClaims())
			body["callback"] = c.callback
			w := f.do(t, http.MethodPost, RequestsPath, f.callerToken(t, "agent-7"), body)
			if w.Code != http.StatusBadRequest || problemType(t, w) != problemGeneric {
				t.Fatalf("expected 400, got %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestInternalIP(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "172.16.0.1": true, "192.168.1.1": true, "169.254.169.254": true,
		"100.64.0.1": true, "0.0.0.0": true, "::1": true, "fd00::1": true, "fe80::1": true,
		"93.184.216.34": false, "2606:2800:220:1::1": false,
	} {
		if got := internalIP(net.ParseIP(addr)); got != want {
			t.Errorf("internalIP(%s) = %v, want %v", addr, got, want)
		}
	}
}
