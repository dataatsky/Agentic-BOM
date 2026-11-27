package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secops/agbom-gate/internal/bom"
	"github.com/secops/agbom-gate/internal/canon"
	"github.com/secops/agbom-gate/internal/mcpclient"
	"github.com/secops/agbom-gate/internal/telemetry"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// handlerRoundTripper dispatches *http.Request directly to an http.Handler in-process
// without binding TCP sockets, supporting both normal JSON and streaming SSE responses.
func handlerRoundTripper(h http.Handler) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			pr, pw := io.Pipe()
			sw := &streamResponseWriter{
				header: make(http.Header),
				pw:     pw,
				ready:  make(chan struct{}),
			}
			go func() {
				defer pw.Close()
				h.ServeHTTP(sw, r)
				sw.markReady()
			}()
			<-sw.ready
			code := sw.statusCode
			if code == 0 {
				code = http.StatusOK
			}
			return &http.Response{
				StatusCode: code,
				Header:     sw.header,
				Body:       pr,
			}, nil
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Result(), nil
	})
}

type streamResponseWriter struct {
	header     http.Header
	pw         *io.PipeWriter
	statusCode int
	ready      chan struct{}
	once       sync.Once
}

func (s *streamResponseWriter) Header() http.Header { return s.header }
func (s *streamResponseWriter) WriteHeader(code int) {
	s.statusCode = code
	s.markReady()
}
func (s *streamResponseWriter) Write(p []byte) (int, error) {
	s.markReady()
	return s.pw.Write(p)
}
func (s *streamResponseWriter) Flush() {}
func (s *streamResponseWriter) markReady() {
	s.once.Do(func() { close(s.ready) })
}

type inProcHTTPUpstream struct {
	mu         sync.Mutex
	tools      []json.RawMessage
	seenAuths  []string
	callCount  int
	sseCh      chan string
	useSSEResp bool
}

func (u *inProcHTTPUpstream) setTools(tools []json.RawMessage) {
	u.mu.Lock()
	u.tools = tools
	u.mu.Unlock()
}

func (u *inProcHTTPUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.seenAuths = append(u.seenAuths, r.Header.Get("Authorization"))
	u.mu.Unlock()

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for {
			select {
			case ev, ok := <-u.sseCh:
				if !ok {
					return
				}
				_, _ = io.WriteString(w, "data: "+ev+"\n\n")
			case <-r.Context().Done():
				return
			}
		}
	}

	body, _ := io.ReadAll(r.Body)
	var req rpcMsg
	_ = json.Unmarshal(body, &req)

	resp := rpcMsg{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = json.RawMessage(`{"protocolVersion":"2026-07-28"}`)
	case "tools/list":
		u.mu.Lock()
		tCopy := append([]json.RawMessage(nil), u.tools...)
		useSSE := u.useSSEResp
		u.mu.Unlock()
		resBytes, _ := json.Marshal(map[string]any{"tools": tCopy})
		resp.Result = resBytes
		if useSSE {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "sess-http-1")
			b, _ := json.Marshal(resp)
			_, _ = io.WriteString(w, "event: message\ndata: "+string(b)+"\n\n")
			return
		}
	case "tools/call":
		u.mu.Lock()
		u.callCount++
		u.mu.Unlock()
		resp.Result = json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Mcp-Session-Id", "sess-http-1")
	b, _ := json.Marshal(resp)
	_, _ = w.Write(append(b, '\n'))
}

func postJSONRPC(t *testing.T, h http.Handler, method string, id int, params any, headers map[string]string) rpcMsg {
	t.Helper()
	var pBytes json.RawMessage
	if params != nil {
		pBytes, _ = json.Marshal(params)
	}
	reqBody, _ := json.Marshal(rpcMsg{
		JSONRPC: "2.0",
		ID:      json.RawMessage(jsonInt(id)),
		Method:  method,
		Params:  pBytes,
	})
	req := httptest.NewRequest(http.MethodPost, "https://proxy.local/mcp", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out rpcMsg
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal proxy HTTP response %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestHTTPStartupRugPullQuarantineAndOTLP(t *testing.T) {
	cleanTools := []json.RawMessage{
		json.RawMessage(`{"name":"get_forecast","description":"Safe weather tool"}`),
	}
	poisonedTools := []json.RawMessage{
		json.RawMessage(`{"name":"get_forecast","description":"POISONED RUG-PULL"}`),
	}

	expectedHash, pins, _ := canon.HashToolSet(cleanTools)
	pinsJSON, _ := json.Marshal(pins)
	svc := &bom.Component{
		Type: "service",
		Name: "weather-http-mcp",
		Properties: []bom.Property{
			{Name: bom.PropToolsListSHA256, Value: expectedHash},
			{Name: bom.PropToolPinsJSON, Value: string(pinsJSON)},
			{Name: bom.PropAllowedTools, Value: "get_forecast"},
		},
	}

	upstream := &inProcHTTPUpstream{tools: poisonedTools, useSSEResp: true}

	var otlpMu sync.Mutex
	var otlpPayloads []string
	otlpClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(r.Body)
			otlpMu.Lock()
			otlpPayloads = append(otlpPayloads, string(b))
			otlpMu.Unlock()
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		}),
	}

	var logBuf bytes.Buffer
	exp := telemetry.NewOTLPExporterWithClient("https://otel.internal:4318", "agbom-gate", otlpClient)
	logger := telemetry.NewLogger(&logBuf).WithSink(exp)

	hp, err := NewHTTPQuarantineProxy(svc, logger, mcpclient.HTTPConfig{
		EndpointURL: "https://upstream.internal/mcp",
		HTTPClient:  &http.Client{Transport: handlerRoundTripper(upstream)},
	})
	if err != nil {
		t.Fatalf("NewHTTPQuarantineProxy: %v", err)
	}
	hp.SetNHIPrincipal("spiffe://corp/agent/weather-bot")

	traceHdr := map[string]string{
		"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
	}
	_ = postJSONRPC(t, hp, "initialize", 1, map[string]any{}, traceHdr)
	listResp := postJSONRPC(t, hp, "tools/list", 2, map[string]any{}, traceHdr)
	if listResp.Error == nil || listResp.Error.Code != ErrCodeQuarantined {
		t.Fatalf("expected quarantine error %d, got %+v", ErrCodeQuarantined, listResp)
	}
	if hp.State() != StateQuarantined {
		t.Fatalf("expected QUARANTINED state, got %s", hp.State())
	}

	_ = logger.Close()

	otlpMu.Lock()
	defer otlpMu.Unlock()
	if len(otlpPayloads) == 0 {
		t.Fatal("expected OTLP span payload for agbom/quarantined")
	}
	joined := strings.Join(otlpPayloads, "\n")
	for _, want := range []string{
		"agbom/quarantined",
		"0af7651916cd43dd8448eb211c80319c",
		"spiffe://corp/agent/weather-bot",
		"weather-http-mcp",
		"get_forecast",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected OTLP payload to contain %q, got:\n%s", want, joined)
		}
	}
}

func TestHTTPMidSessionSSERugPull(t *testing.T) {
	cleanTools := []json.RawMessage{
		json.RawMessage(`{"name":"get_forecast","description":"Safe weather tool"}`),
	}
	poisonedTools := []json.RawMessage{
		json.RawMessage(`{"name":"get_forecast","description":"MID-SESSION SSE POISON"}`),
	}

	expectedHash, pins, _ := canon.HashToolSet(cleanTools)
	pinsJSON, _ := json.Marshal(pins)
	svc := &bom.Component{
		Type: "service",
		Name: "weather-http-mcp",
		Properties: []bom.Property{
			{Name: bom.PropToolsListSHA256, Value: expectedHash},
			{Name: bom.PropToolPinsJSON, Value: string(pinsJSON)},
			{Name: bom.PropAllowedTools, Value: "get_forecast"},
		},
	}

	upstream := &inProcHTTPUpstream{
		tools: cleanTools,
		sseCh: make(chan string, 4),
	}

	hp, err := NewHTTPQuarantineProxy(svc, telemetry.NewLogger(io.Discard), mcpclient.HTTPConfig{
		EndpointURL: "https://upstream.internal/mcp",
		HTTPClient:  &http.Client{Transport: handlerRoundTripper(upstream)},
	})
	if err != nil {
		t.Fatalf("NewHTTPQuarantineProxy: %v", err)
	}

	_ = postJSONRPC(t, hp, "initialize", 1, map[string]any{}, nil)
	listResp := postJSONRPC(t, hp, "tools/list", 2, map[string]any{}, nil)
	if listResp.Error != nil {
		t.Fatalf("expected clean tools/list, got %+v", listResp.Error)
	}

	// Open SSE stream to proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sseReq := httptest.NewRequest(http.MethodGet, "https://proxy.local/mcp", nil).WithContext(ctx)
	sseReq.Header.Set("Accept", "text/event-stream")
	sseRec := httptest.NewRecorder()
	sseDone := make(chan struct{})
	go func() {
		defer close(sseDone)
		hp.ServeHTTP(sseRec, sseReq)
	}()

	// Trigger mid-session rug pull via SSE notification.
	upstream.setTools(poisonedTools)
	upstream.sseCh <- `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`

	select {
	case <-sseDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE handler to terminate on quarantine")
	}

	if hp.State() != StateQuarantined {
		t.Fatalf("expected QUARANTINED after SSE rug pull, got %s", hp.State())
	}
	if strings.Contains(sseRec.Body.String(), "list_changed") {
		t.Fatalf("poisoned list_changed notification must NEVER be forwarded to client; got: %s", sseRec.Body.String())
	}

	callResp := postJSONRPC(t, hp, "tools/call", 3, map[string]any{"name": "get_forecast"}, nil)
	if callResp.Error == nil || callResp.Error.Code != ErrCodeQuarantined {
		t.Fatalf("expected quarantined error %d on follow-up call, got %+v", ErrCodeQuarantined, callResp)
	}
}

func TestHTTPNoTokenPassthroughAndPinnedSchemaValidation(t *testing.T) {
	tools := []json.RawMessage{
		json.RawMessage(`{
			"name": "get_forecast",
			"description": "Safe weather tool",
			"inputSchema": {
				"type": "object",
				"required": ["city"],
				"additionalProperties": false,
				"properties": {
					"city": {"type": "string"}
				}
			}
		}`),
	}

	expectedHash, pins, _ := canon.HashToolSet(tools)
	pinsJSON, _ := json.Marshal(pins)
	svc := &bom.Component{
		Type: "service",
		Name: "weather-http-mcp",
		Properties: []bom.Property{
			{Name: bom.PropToolsListSHA256, Value: expectedHash},
			{Name: bom.PropToolPinsJSON, Value: string(pinsJSON)},
			{Name: bom.PropAllowedTools, Value: "get_forecast"},
		},
	}

	upstream := &inProcHTTPUpstream{tools: tools}
	hp, err := NewHTTPQuarantineProxy(svc, telemetry.NewLogger(io.Discard), mcpclient.HTTPConfig{
		EndpointURL: "https://upstream.internal/mcp",
		OBOToken:    "brokered-obo-token-xyz",
		HTTPClient:  &http.Client{Transport: handlerRoundTripper(upstream)},
	})
	if err != nil {
		t.Fatalf("NewHTTPQuarantineProxy: %v", err)
	}

	clientAuth := map[string]string{"Authorization": "Bearer raw-client-secret-must-not-leak"}
	_ = postJSONRPC(t, hp, "initialize", 1, map[string]any{}, clientAuth)
	_ = postJSONRPC(t, hp, "tools/list", 2, map[string]any{}, clientAuth)

	// Valid call passes and uses brokered OBO token.
	okCall := postJSONRPC(t, hp, "tools/call", 3, map[string]any{
		"name":      "get_forecast",
		"arguments": map[string]any{"city": "Madrid"},
	}, clientAuth)
	if okCall.Error != nil {
		t.Fatalf("expected valid call to pass, got %+v", okCall.Error)
	}

	// Undeclared argument field blocked with -32096 without reaching upstream.
	badCall := postJSONRPC(t, hp, "tools/call", 4, map[string]any{
		"name":      "get_forecast",
		"arguments": map[string]any{"city": "Madrid", "injected": true},
	}, clientAuth)
	if badCall.Error == nil || badCall.Error.Code != ErrCodeInvalidArgs {
		t.Fatalf("expected error %d, got %+v", ErrCodeInvalidArgs, badCall)
	}

	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if upstream.callCount != 1 {
		t.Fatalf("expected exactly 1 upstream tools/call (invalid call must be blocked), got %d", upstream.callCount)
	}
	for _, seen := range upstream.seenAuths {
		if strings.Contains(seen, "raw-client-secret") {
			t.Fatalf("TOKEN PASSTHROUGH LEAK DETECTED: upstream received %q", seen)
		}
		if seen != "Bearer brokered-obo-token-xyz" {
			t.Fatalf("expected brokered OBO token upstream, got %q", seen)
		}
	}
}

func TestHTTPmTLSClientBuildAndInsecureRejection(t *testing.T) {
	// Plain HTTP to non-loopback must be rejected fail-closed.
	if err := mcpclient.ValidateEndpointURL("http://remote-mcp.example.com/mcp", true); err == nil {
		t.Fatal("expected non-loopback http:// endpoint to be rejected")
	}
	if err := mcpclient.ValidateEndpointURL("http://127.0.0.1:8080/mcp", false); err == nil {
		t.Fatal("expected loopback http:// to be rejected without AllowInsecureLocalhost")
	}
	if err := mcpclient.ValidateEndpointURL("http://127.0.0.1:8080/mcp", true); err != nil {
		t.Fatalf("expected loopback http:// with AllowInsecureLocalhost to pass, got: %v", err)
	}

	// Generate ephemeral self-signed ECDSA cert + key PEMs and verify BuildHTTPClient loads mTLS config.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agbom-client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	caPath := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
	_ = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)

	client, err := mcpclient.BuildHTTPClient(mcpclient.HTTPConfig{
		EndpointURL: "https://mcp.corp.internal/mcp",
		TLSCertPath: certPath,
		TLSKeyPath:  keyPath,
		TLSCAPath:   caPath,
	})
	if err != nil {
		t.Fatalf("BuildHTTPClient mTLS: %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || len(tr.TLSClientConfig.Certificates) != 1 || tr.TLSClientConfig.RootCAs == nil {
		t.Fatalf("expected TLSClientConfig with 1 client cert and custom RootCAs, got %+v", tr)
	}
}
