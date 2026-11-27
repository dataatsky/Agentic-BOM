package telemetry

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// ACSEvent emits structured DFIR telemetry aligned with OWASP Agent Control Standard (ACS).
type ACSEvent struct {
	Timestamp    string   `json:"timestamp"`
	EventType    string   `json:"event_type"` // agbom/snapshot, agbom/quarantined, agbom/tool_blocked
	Severity     string   `json:"severity"`   // INFO, WARN, CRITICAL
	ServerName   string   `json:"server_name"`
	NHIPrincipal string   `json:"nhi_principal,omitempty"`
	TraceParent  string   `json:"traceparent,omitempty"`
	ExpectedHash string   `json:"expected_hash,omitempty"`
	ObservedHash string   `json:"observed_hash,omitempty"`
	DriftedTools []string `json:"drifted_tools,omitempty"`
	RedactedDiff string   `json:"redacted_diff,omitempty"`
	ToolName     string   `json:"tool_name,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// SpanSink receives ACS events for secondary telemetry export (e.g., OTLP traces).
type SpanSink interface {
	ExportEvent(ev ACSEvent)
	Close() error
}

type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	sink SpanSink
}

func NewLogger(w io.Writer) *Logger {
	return &Logger{w: w}
}

// WithSink attaches an optional secondary SpanSink (such as OTLPExporter) to the logger.
func (l *Logger) WithSink(sink SpanSink) *Logger {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	l.sink = sink
	l.mu.Unlock()
	return l
}

// Close flushes any attached secondary SpanSink.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	sink := l.sink
	l.mu.Unlock()
	if sink != nil {
		return sink.Close()
	}
	return nil
}

func (l *Logger) Emit(ev ACSEvent) {
	if l == nil {
		return
	}
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	l.mu.Lock()
	w := l.w
	sink := l.sink
	if w != nil {
		if b, err := json.Marshal(ev); err == nil {
			_, _ = w.Write(append(b, '\n'))
		}
	}
	l.mu.Unlock()

	if sink != nil {
		sink.ExportEvent(ev)
	}
}
