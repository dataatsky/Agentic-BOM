package telemetry

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestOTLPExporterSendsACSSpans(t *testing.T) {
	var mu sync.Mutex
	var received []otlpExportTraceRequest
	var paths []string
	var contentTypes []string

	mockClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			var req otlpExportTraceRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("unmarshal otlp payload: %v", err)
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader("bad request")),
				}, nil
			}
			mu.Lock()
			paths = append(paths, r.URL.Path)
			contentTypes = append(contentTypes, r.Header.Get("Content-Type"))
			received = append(received, req)
			mu.Unlock()
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			}, nil
		}),
	}

	var ndjson bytes.Buffer
	exp := NewOTLPExporterWithClient("http://collector.internal:4318", "agbom-gate-test", mockClient)
	logger := NewLogger(&ndjson).WithSink(exp)

	logger.Emit(ACSEvent{
		EventType:    "agbom/quarantined",
		Severity:     "CRITICAL",
		ServerName:   "weather-mcp",
		NHIPrincipal: "spiffe://corp/agent/secops-triage",
		TraceParent:  "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		ExpectedHash: "expected123",
		ObservedHash: "observed456",
		DriftedTools: []string{"get_forecast"},
		Reason:       "tools_list_sha256 mismatch against signed AgBOM",
	})

	if err := logger.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 OTLP trace batch, got %d", len(received))
	}
	if paths[0] != "/v1/traces" {
		t.Fatalf("expected /v1/traces path, got %s", paths[0])
	}
	if contentTypes[0] != "application/json" {
		t.Fatalf("expected application/json Content-Type, got %s", contentTypes[0])
	}

	span := received[0].ResourceSpans[0].ScopeSpans[0].Spans[0]
	if span.Name != "agbom/quarantined" {
		t.Fatalf("expected span name agbom/quarantined, got %s", span.Name)
	}
	if span.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("expected propagated traceId, got %s", span.TraceID)
	}
	if span.ParentSpanID != "00f067aa0ba902b7" {
		t.Fatalf("expected propagated parentSpanId, got %s", span.ParentSpanID)
	}
	if span.Status.Code != otlpStatusError {
		t.Fatalf("expected ERROR status code %d, got %d", otlpStatusError, span.Status.Code)
	}

	attrMap := map[string]otlpAnyValue{}
	for _, kv := range span.Attributes {
		attrMap[kv.Key] = kv.Value
	}
	if attrMap["agbom.server.name"].StringValue != "weather-mcp" {
		t.Fatalf("unexpected agbom.server.name: %+v", attrMap["agbom.server.name"])
	}
	if attrMap["agbom.tools_list.sha256"].StringValue != "expected123" {
		t.Fatalf("unexpected agbom.tools_list.sha256: %+v", attrMap["agbom.tools_list.sha256"])
	}
	if attrMap["agbom.nhi.principal"].StringValue != "spiffe://corp/agent/secops-triage" {
		t.Fatalf("unexpected agbom.nhi.principal: %+v", attrMap["agbom.nhi.principal"])
	}
	driftArr := attrMap["agbom.drift.tools"].ArrayValue
	if driftArr == nil || len(driftArr.Values) != 1 || driftArr.Values[0].StringValue != "get_forecast" {
		t.Fatalf("unexpected agbom.drift.tools: %+v", driftArr)
	}

	// Ensure local NDJSON log was also written.
	if !bytes.Contains(ndjson.Bytes(), []byte(`"event_type":"agbom/quarantined"`)) {
		t.Fatalf("expected NDJSON log entry, got: %s", ndjson.String())
	}
}
