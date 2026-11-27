package reconcile

import (
	"strings"
	"testing"

	"github.com/secops/agbom-gate/internal/bom"
	"github.com/secops/agbom-gate/internal/telemetry"
)

func TestReconcileDetectsShadowServersToolsStoresAndDrift(t *testing.T) {
	declared := &bom.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []bom.Component{
			{
				Type: "service",
				Name: "weather-mcp",
				Properties: []bom.Property{
					{Name: bom.PropToolsListSHA256, Value: "aaaa1111aaaa1111"},
					{Name: bom.PropAllowedTools, Value: "get_forecast"},
				},
			},
			{
				Type: "data",
				Name: "ir-playbook-vector-store",
				Properties: []bom.Property{
					{Name: bom.PropAccessMode, Value: "read-only"},
				},
			},
		},
	}

	// Clean NDJSON observation passes reconciliation.
	cleanNDJSON := []byte(`{"event_type":"agbom/snapshot","server_name":"weather-mcp","observed_hash":"aaaa1111aaaa1111","data_store":"ir-playbook-vector-store"}` + "\n")
	cleanObs, err := ParseTelemetry(cleanNDJSON)
	if err != nil {
		t.Fatalf("ParseTelemetry clean: %v", err)
	}
	cleanRes := Reconcile(declared, cleanObs)
	if cleanRes.ExitCode != 0 {
		t.Fatalf("expected clean reconciliation exit 0, got %d:\n%s", cleanRes.ExitCode, cleanRes.Markdown)
	}

	// Mixed NDJSON + OTLP payload containing shadow server, shadow data store, undeclared tool, and hash drift.
	otlpBytes, err := telemetry.BuildOTLPPayload("agbom-gate", telemetry.ACSEvent{
		EventType:    "agbom/quarantined",
		Severity:     "CRITICAL",
		ServerName:   "weather-mcp",
		ObservedHash: "bbbb2222bbbb2222",
		DriftedTools: []string{"get_forecast"},
	})
	if err != nil {
		t.Fatalf("BuildOTLPPayload: %v", err)
	}

	ndjsonLog := strings.Join([]string{
		`{"event_type":"agbom/snapshot","server_name":"rogue-shadow-mcp","observed_hash":"deadbeef"}`,
		`{"event_type":"agbom/tool_blocked","server_name":"weather-mcp","tool_name":"delete_all_records"}`,
		`{"event_type":"agbom/access","data_store":"unapproved-prod-db"}`,
		string(otlpBytes),
	}, "\n")

	obs, err := ParseTelemetry([]byte(ndjsonLog))
	if err != nil {
		t.Fatalf("ParseTelemetry adversarial: %v", err)
	}
	res := Reconcile(declared, obs)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2 on shadow capabilities & drift, got %d", res.ExitCode)
	}
	for _, wantCode := range []string{
		"SHADOW_MCP_SERVER",
		"SHADOW_DATA_STORE",
		"UNDECLARED_TOOL_CALL",
		"RUNTIME_HASH_DRIFT",
		"QUARANTINE_EVENT_OBSERVED",
	} {
		if !strings.Contains(res.Markdown, wantCode) {
			t.Fatalf("expected %s in reconciliation report, got:\n%s", wantCode, res.Markdown)
		}
	}
}

func TestReconcileEmptyAllowedToolsFailsClosed(t *testing.T) {
	declared := &bom.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []bom.Component{
			{
				Type: "service",
				Name: "weather-mcp",
				Properties: []bom.Property{
					{Name: bom.PropToolsListSHA256, Value: "aaaa1111aaaa1111"},
					{Name: bom.PropAllowedTools, Value: ""},
				},
			},
		},
	}

	obs, err := ParseTelemetry([]byte(`{"event_type":"agbom/tool_blocked","server_name":"weather-mcp","tool_name":"get_forecast"}` + "\n"))
	if err != nil {
		t.Fatalf("ParseTelemetry: %v", err)
	}
	res := Reconcile(declared, obs)
	if res.ExitCode != 2 || !strings.Contains(res.Markdown, "UNDECLARED_TOOL_CALL") {
		t.Fatalf("expected empty allowed_tools to fail closed with UNDECLARED_TOOL_CALL, got exit=%d:\n%s", res.ExitCode, res.Markdown)
	}
}
