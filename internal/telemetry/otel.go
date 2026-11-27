package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	otlpStatusUnset = 0
	otlpStatusOK    = 1
	otlpStatusError = 2
	otlpKindServer  = 2
)

// OTLPExporter ships OWASP ACS events as OpenTelemetry spans over OTLP/HTTP JSON (/v1/traces).
// It uses a bounded non-blocking queue so collector unavailability never blocks proxy enforcement.
type OTLPExporter struct {
	tracesURL   string
	serviceName string
	client      *http.Client

	ch        chan ACSEvent
	wg        sync.WaitGroup
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
}

// NewOTLPExporter creates an OTLP/HTTP JSON trace exporter targeting endpoint.
// If endpoint does not already end in /v1/traces, it is appended automatically.
func NewOTLPExporter(endpoint, serviceName string) *OTLPExporter {
	return NewOTLPExporterWithClient(endpoint, serviceName, &http.Client{Timeout: 3 * time.Second})
}

// NewOTLPExporterWithClient creates an OTLP/HTTP JSON trace exporter using a custom *http.Client.
func NewOTLPExporterWithClient(endpoint, serviceName string, client *http.Client) *OTLPExporter {
	ep := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if ep != "" && !strings.HasSuffix(ep, "/v1/traces") {
		ep += "/v1/traces"
	}
	if serviceName == "" {
		serviceName = "agbom-gate"
	}
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	exp := &OTLPExporter{
		tracesURL:   ep,
		serviceName: serviceName,
		client:      client,
		ch:          make(chan ACSEvent, 256),
	}
	exp.wg.Add(1)
	go exp.worker()
	return exp
}

// ExportEvent enqueues an ACSEvent for asynchronous OTLP/HTTP export.
func (e *OTLPExporter) ExportEvent(ev ACSEvent) {
	if e == nil || e.tracesURL == "" {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	select {
	case e.ch <- ev:
	default:
		// Drop rather than stall the security data plane if collector is backlogged.
	}
	e.mu.Unlock()
}

// Close drains queued spans and waits for in-flight HTTP exports to finish.
func (e *OTLPExporter) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		close(e.ch)
		e.mu.Unlock()
		e.wg.Wait()
	})
	return nil
}

func (e *OTLPExporter) worker() {
	defer e.wg.Done()
	for ev := range e.ch {
		e.sendSingle(ev)
	}
}

func (e *OTLPExporter) sendSingle(ev ACSEvent) {
	payload, err := BuildOTLPPayload(e.serviceName, ev)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tracesURL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// BuildOTLPPayload converts an ACSEvent into an OTLP/HTTP JSON ExportTraceServiceRequest.
func BuildOTLPPayload(serviceName string, ev ACSEvent) ([]byte, error) {
	traceID, parentSpanID := parseTraceParent(ev.TraceParent)
	if traceID == "" {
		traceID = randomHex(16)
	}
	spanID := randomHex(8)

	ts := time.Now().UTC()
	if ev.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil {
			ts = parsed.UTC()
		}
	}
	startNano := strconv.FormatInt(ts.UnixNano(), 10)
	endNano := strconv.FormatInt(ts.Add(time.Microsecond).UnixNano(), 10)

	attrs := []otlpKeyValue{
		kvString("agbom.server.name", ev.ServerName),
		kvString("agbom.event.type", ev.EventType),
		kvString("agbom.event.severity", ev.Severity),
	}
	if ev.ExpectedHash != "" {
		attrs = append(attrs, kvString("agbom.tools_list.sha256", ev.ExpectedHash))
	}
	if ev.ObservedHash != "" {
		attrs = append(attrs, kvString("agbom.tools_list.observed_sha256", ev.ObservedHash))
	}
	if len(ev.DriftedTools) > 0 {
		attrs = append(attrs, kvStringArray("agbom.drift.tools", ev.DriftedTools))
	}
	if ev.RedactedDiff != "" {
		attrs = append(attrs, kvString("agbom.drift.redacted_diff", ev.RedactedDiff))
	}
	if ev.NHIPrincipal != "" {
		attrs = append(attrs, kvString("agbom.nhi.principal", ev.NHIPrincipal))
	}
	if ev.ToolName != "" {
		attrs = append(attrs, kvString("agbom.tool.name", ev.ToolName))
	}
	if ev.Reason != "" {
		attrs = append(attrs, kvString("agbom.event.reason", ev.Reason))
	}

	statusCode := otlpStatusOK
	statusMsg := ""
	switch strings.ToUpper(ev.Severity) {
	case "CRITICAL", "WARN":
		statusCode = otlpStatusError
		statusMsg = ev.Reason
	case "INFO":
		statusCode = otlpStatusOK
	default:
		statusCode = otlpStatusUnset
	}

	spanName := ev.EventType
	if spanName == "" {
		spanName = "agbom/event"
	}

	span := otlpSpan{
		TraceID:           traceID,
		SpanID:            spanID,
		ParentSpanID:      parentSpanID,
		Name:              spanName,
		Kind:              otlpKindServer,
		StartTimeUnixNano: startNano,
		EndTimeUnixNano:   endNano,
		Attributes:        attrs,
		Status: otlpStatus{
			Code:    statusCode,
			Message: statusMsg,
		},
	}

	req := otlpExportTraceRequest{
		ResourceSpans: []otlpResourceSpan{
			{
				Resource: otlpResource{
					Attributes: []otlpKeyValue{
						kvString("service.name", serviceName),
						kvString("telemetry.sdk.name", "agbom-gate-otlp"),
						kvString("telemetry.sdk.language", "go"),
					},
				},
				ScopeSpans: []otlpScopeSpan{
					{
						Scope: otlpInstrumentationScope{
							Name:    "github.com/secops/agbom-gate/internal/telemetry",
							Version: "0.2.0",
						},
						Spans: []otlpSpan{span},
					},
				},
			},
		},
	}
	return json.Marshal(req)
}

// parseTraceParent extracts trace-id (32 hex chars) and parent-id (16 hex chars)
// from a W3C traceparent header ("00-<trace-id>-<parent-id>-<flags>").
func parseTraceParent(hdr string) (traceID, parentSpanID string) {
	parts := strings.Split(strings.TrimSpace(hdr), "-")
	if len(parts) != 4 {
		return "", ""
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		return "", ""
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", ""
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", ""
	}
	// Reject all-zero IDs per W3C Trace Context spec.
	if strings.Trim(parts[1], "0") == "" || strings.Trim(parts[2], "0") == "" {
		return "", ""
	}
	return strings.ToLower(parts[1]), strings.ToLower(parts[2])
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type otlpExportTraceRequest struct {
	ResourceSpans []otlpResourceSpan `json:"resourceSpans"`
}

type otlpResourceSpan struct {
	Resource   otlpResource    `json:"resource"`
	ScopeSpans []otlpScopeSpan `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeSpan struct {
	Scope otlpInstrumentationScope `json:"scope"`
	Spans []otlpSpan               `json:"spans"`
}

type otlpInstrumentationScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes"`
	Status            otlpStatus     `json:"status"`
}

type otlpStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue string          `json:"stringValue,omitempty"`
	ArrayValue  *otlpArrayValue `json:"arrayValue,omitempty"`
}

type otlpArrayValue struct {
	Values []otlpAnyValue `json:"values"`
}

func kvString(k, v string) otlpKeyValue {
	return otlpKeyValue{
		Key:   k,
		Value: otlpAnyValue{StringValue: v},
	}
}

func kvStringArray(k string, vals []string) otlpKeyValue {
	arr := make([]otlpAnyValue, 0, len(vals))
	for _, v := range vals {
		arr = append(arr, otlpAnyValue{StringValue: v})
	}
	return otlpKeyValue{
		Key:   k,
		Value: otlpAnyValue{ArrayValue: &otlpArrayValue{Values: arr}},
	}
}
