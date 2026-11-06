package ars

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Tracefort-io/opa-authzen-plugin/internal/ars/store"
)

// Callback Notifications Profile. A task that becomes terminal gets an
// outbox row in the same transaction (store); workers on every replica
// claim and send them. Notifications never carry a result: the PEP reads
// the Task Status Endpoint, which stays authoritative.

const (
	maxCallbackState    = 1024
	callbackBatch       = 16
	callbackPoll        = 2 * time.Second
	callbackBackoffBase = 5 * time.Second
	callbackBackoffMax  = time.Hour
	callbackResponseMax = 64 << 10

	// Headers of a notification. The profile leaves the authentication
	// mechanism to the deployment; these names are this plugin's.
	SignatureHeader = "X-AuthZEN-Signature"
	DeliveryHeader  = "X-AuthZEN-Delivery"
)

// CallbackConfig enables callbacks for the listed destinations.
type CallbackConfig struct {
	Timeout     time.Duration
	MaxAttempts int
	// Destinations are keyed by lower-case host name or IP literal.
	Destinations map[string]CallbackDestination
	// RootCAs replaces the system roots for callback TLS. Tests only.
	RootCAs *x509.CertPool
	// Resolve looks up a host at submission; nil uses the system resolver.
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
}

// CallbackDestination is one allowed callback host.
type CallbackDestination struct {
	// Secret keys the HMAC-SHA256 signature of every notification to it.
	Secret []byte
	// AllowInternal permits loopback, private and other internal addresses.
	AllowInternal bool
}

var callbackEvents = []string{
	store.StatusApproved, store.StatusDenied, store.StatusExpired,
	store.StatusCancelled, store.StatusFailed, store.StatusPartial,
}

// parseCallback validates the submission's `callback` member. The endpoint
// must be an https URL on a configured destination that does not resolve
// to an internal address unless the destination allows it.
func (s *Service) parseCallback(ctx context.Context, raw any) (*store.Callback, string) {
	cfg := s.d.Callbacks
	if cfg == nil {
		return nil, "callbacks are not enabled on this service; poll the status endpoint"
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, "callback must be a JSON object"
	}
	cb := &store.Callback{}
	cb.Endpoint, _ = obj["endpoint"].(string)
	u, err := url.Parse(cb.Endpoint)
	if cb.Endpoint == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, "callback.endpoint must be an https URL without credentials or fragment"
	}
	host := strings.ToLower(u.Hostname())
	dest, ok := cfg.Destinations[host]
	if !ok {
		return nil, "callback.endpoint is not on an allowed destination"
	}
	ips, err := s.resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, "callback.endpoint does not resolve"
	}
	if !dest.AllowInternal && slices.ContainsFunc(ips, internalIP) {
		return nil, "callback.endpoint resolves to an internal address"
	}
	if v, has := obj["state"]; has {
		state, ok := v.(string)
		if !ok || len(state) > maxCallbackState {
			return nil, fmt.Sprintf("callback.state must be a string of at most %d bytes", maxCallbackState)
		}
		cb.State = state
	}
	if v, has := obj["events"]; has {
		list, ok := v.([]any)
		if !ok || len(list) == 0 {
			return nil, "callback.events must be a non-empty array"
		}
		for _, e := range list {
			name, _ := e.(string)
			if !slices.Contains(callbackEvents, name) {
				return nil, "callback.events must name events from " + strings.Join(callbackEvents, ", ")
			}
			if !slices.Contains(cb.Events, name) {
				cb.Events = append(cb.Events, name)
			}
		}
	}
	return cb, ""
}

func (s *Service) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if s.d.Callbacks.Resolve != nil {
		return s.d.Callbacks.Resolve(ctx, host)
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// sharedAddressSpace is RFC 6598 carrier-grade NAT space, internal to the
// network that hands it out.
var sharedAddressSpace = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// internalIP reports loopback, link-local, private-use and other addresses
// that do not lead to the public internet.
func internalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		sharedAddressSpace.Contains(ip) || (ip.To4() != nil && ip.To4()[0] == 0)
}

// newCallbackClient builds the HTTP client for notifications. The address
// check is repeated on the IP actually dialled, so a host that resolved to
// a public address at submission cannot be rebound to an internal one.
// Proxies from the environment are ignored and redirects are not followed.
func newCallbackClient(cfg *CallbackConfig) *http.Client {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		dest, ok := cfg.Destinations[strings.ToLower(host)]
		if !ok {
			return nil, fmt.Errorf("callback host %s is not an allowed destination", host)
		}
		d := net.Dialer{Timeout: cfg.Timeout, Control: func(_, address string, _ syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(h)
			if ip == nil || (!dest.AllowInternal && internalIP(ip)) {
				return fmt.Errorf("callback to internal address %s refused", h)
			}
			return nil
		}}
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			DialContext:           dial,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
			TLSHandshakeTimeout:   cfg.Timeout,
			ResponseHeaderTimeout: cfg.Timeout,
			MaxIdleConns:          16,
			IdleConnTimeout:       90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// RunCallbacks delivers due notifications until ctx is done. Every replica
// runs one; the store's claims keep them from sending one twice at once.
func (s *Service) RunCallbacks(ctx context.Context) {
	if s.d.Callbacks == nil {
		return
	}
	ticker := time.NewTicker(callbackPoll)
	defer ticker.Stop()
	for {
		s.deliverDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// deliverDue claims a batch of due notifications and sends them in
// parallel. The lease covers one attempt with time to record its outcome.
func (s *Service) deliverDue(ctx context.Context) {
	lease := 2*s.d.Callbacks.Timeout + 10*time.Second
	due, err := s.d.Store.ClaimCallbacks(ctx, s.now(), lease, callbackBatch)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.d.Logger.Error("AuthZEN access request service: claiming callbacks: %v", err)
		}
		return
	}
	var wg sync.WaitGroup
	for _, d := range due {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.deliver(ctx, d)
		}()
	}
	wg.Wait()
}

// deliver sends one notification and records the outcome.
func (s *Service) deliver(ctx context.Context, d store.Delivery) {
	t, err := s.d.Store.GetTask(ctx, d.TaskID)
	if errors.Is(err, store.ErrNotFound) {
		s.failCallback(ctx, d, nil, "the task no longer exists")
		return
	}
	if err != nil {
		s.retryCallback(ctx, d, nil, err.Error())
		return
	}
	if err := s.post(ctx, t, d); err != nil {
		if d.Attempts >= s.d.Callbacks.MaxAttempts {
			s.failCallback(ctx, d, t, err.Error())
		} else {
			s.retryCallback(ctx, d, t, err.Error())
		}
		return
	}
	if err := s.d.Store.MarkDelivered(ctx, d.ID, s.now()); err != nil {
		s.d.Logger.Error("AuthZEN access request service: recording callback delivery: %v", err)
		return
	}
	attrs := s.auditTask(t, nil)
	attrs["event"], attrs["endpoint"], attrs["attempts"] = d.Event, t.Callback.Endpoint, strconv.Itoa(d.Attempts)
	s.d.Audit.Emit(ctx, "callback_delivered", attrs)
}

func (s *Service) retryCallback(ctx context.Context, d store.Delivery, t *store.Task, reason string) {
	next := s.now().Add(callbackBackoff(d.Attempts))
	if err := s.d.Store.RetryCallback(ctx, d.ID, next, reason); err != nil {
		s.d.Logger.Error("AuthZEN access request service: scheduling callback retry: %v", err)
	}
	if t != nil {
		s.d.Logger.Warn("AuthZEN access request service: callback for task %s failed (attempt %d): %s", t.ID, d.Attempts, reason)
	}
}

func (s *Service) failCallback(ctx context.Context, d store.Delivery, t *store.Task, reason string) {
	if err := s.d.Store.FailCallback(ctx, d.ID, s.now(), reason); err != nil {
		s.d.Logger.Error("AuthZEN access request service: recording callback failure: %v", err)
		return
	}
	attrs := map[string]any{"task_id": d.TaskID, "actor": "system"}
	if t != nil {
		attrs = s.auditTask(t, nil)
		attrs["endpoint"] = t.Callback.Endpoint
	}
	attrs["event"], attrs["attempts"], attrs["error"] = d.Event, strconv.Itoa(d.Attempts), reason
	s.d.Audit.Emit(ctx, "callback_failed", attrs)
}

// callbackBackoff doubles from the base per attempt, up to the maximum,
// with up to 20% jitter so replicas do not retry in lockstep.
func callbackBackoff(attempts int) time.Duration {
	d := callbackBackoffBase
	for i := 1; i < attempts && d < callbackBackoffMax; i++ {
		d *= 2
	}
	d = min(d, callbackBackoffMax)
	return d + rand.N(d/5+1)
}

// callbackBody is the notification: the task handle's identity and status
// and the PEP's state, never a result.
func (s *Service) callbackBody(t *store.Task) map[string]any {
	task := map[string]any{"id": t.ID, "status": t.Status, "status_endpoint": s.statusEndpoint(t.ID)}
	if t.Bulk {
		items := make([]any, len(t.Items))
		for i, it := range t.Items {
			items[i] = map[string]any{"status": it.Status}
		}
		task["items"] = items
	}
	body := map[string]any{"task": task}
	if t.Callback.State != "" {
		body["state"] = t.Callback.State
	}
	return body
}

// post sends a notification, signed with the destination's key.
func (s *Service) post(ctx context.Context, t *store.Task, d store.Delivery) error {
	u, err := url.Parse(t.Callback.Endpoint)
	if err != nil {
		return err
	}
	dest, ok := s.d.Callbacks.Destinations[strings.ToLower(u.Hostname())]
	if !ok {
		return fmt.Errorf("%s is no longer an allowed destination", u.Hostname())
	}
	body, err := json.Marshal(s.callbackBody(t))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Callback.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(s.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, "t="+ts+",v1="+SignCallback(dest.Secret, ts, body))
	req.Header.Set(DeliveryHeader, strconv.FormatInt(d.ID, 10))
	resp, err := s.callbackClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, callbackResponseMax))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("callback endpoint answered %d", resp.StatusCode)
	}
	return nil
}

// SignCallback is the hex HMAC-SHA256 of "<timestamp>.<body>", the v1 value
// of the signature header a receiver recomputes to authenticate a
// notification.
func SignCallback(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
