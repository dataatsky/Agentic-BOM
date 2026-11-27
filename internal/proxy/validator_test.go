package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/secops/agbom-gate/internal/bom"
	"github.com/secops/agbom-gate/internal/canon"
)

func TestCompiledSchemaValidationCore(t *testing.T) {
	rawSchema := json.RawMessage(`{
		"type": "object",
		"required": ["city", "days"],
		"additionalProperties": false,
		"properties": {
			"city": { "type": "string", "minLength": 2, "maxLength": 50, "pattern": "^[A-Za-z ]+$" },
			"days": { "type": "integer", "minimum": 1, "maximum": 7 },
			"units": { "type": "string", "enum": ["metric", "imperial"] },
			"tags": {
				"type": "array",
				"maxItems": 3,
				"uniqueItems": true,
				"items": { "type": "string" }
			}
		}
	}`)

	cs, err := CompileInputSchema(rawSchema)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	// Valid arguments
	if err := cs.ValidateArguments(json.RawMessage(`{"city":"Barcelona","days":3,"units":"metric","tags":["uv","rain"]}`)); err != nil {
		t.Fatalf("expected valid arguments to pass, got: %v", err)
	}

	cases := []struct {
		name string
		args string
		want string
	}{
		{
			name: "additionalProperties false rejects argument stuffing",
			args: `{"city":"Barcelona","days":3,"__override_header":"Bearer steal"}`,
			want: "additional property",
		},
		{
			name: "missing required field",
			args: `{"city":"Barcelona"}`,
			want: `missing required property "days"`,
		},
		{
			name: "non-integer float for integer field",
			args: `{"city":"Barcelona","days":2.5}`,
			want: "expected type integer",
		},
		{
			name: "pattern mismatch",
			args: `{"city":"Barcelona; rm -rf /","days":3}`,
			want: "pattern",
		},
		{
			name: "enum mismatch",
			args: `{"city":"Barcelona","days":3,"units":"kelvin"}`,
			want: "enum",
		},
		{
			name: "uniqueItems violation",
			args: `{"city":"Barcelona","days":3,"tags":["uv","uv"]}`,
			want: "uniqueItems",
		},
		{
			name: "exceeds maximum",
			args: `{"city":"Barcelona","days":14}`,
			want: "maximum",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cs.ValidateArguments(json.RawMessage(tc.args))
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestProxyRejectsInvalidArgumentsAgainstPinnedSchema(t *testing.T) {
	tools := []json.RawMessage{
		json.RawMessage(`{
			"name": "get_forecast",
			"description": "Returns forecast",
			"inputSchema": {
				"type": "object",
				"required": ["city"],
				"additionalProperties": false,
				"properties": {
					"city": { "type": "string", "minLength": 1 }
				}
			}
		}`),
	}

	expectedHash, pins, err := canon.HashToolSet(tools)
	if err != nil {
		t.Fatalf("hash tools: %v", err)
	}
	pinsJSON, _ := json.Marshal(pins)
	svc := &bom.Component{
		Type: "service",
		Name: "weather-mcp",
		Properties: []bom.Property{
			{Name: bom.PropToolsListSHA256, Value: expectedHash},
			{Name: bom.PropToolPinsJSON, Value: string(pinsJSON)},
			{Name: bom.PropAllowedTools, Value: "get_forecast"},
		},
	}

	send, _, _, readLog, cleanup := startProxyHarness(t, svc, tools)
	defer cleanup()

	_ = send("initialize", 1, map[string]any{})
	listResp := send("tools/list", 2, map[string]any{})
	if listResp.Error != nil {
		t.Fatalf("unexpected tools/list error: %+v", listResp.Error)
	}

	// Valid call succeeds.
	okResp := send("tools/call", 3, map[string]any{
		"name":      "get_forecast",
		"arguments": map[string]any{"city": "Barcelona"},
	})
	if okResp.Error != nil {
		t.Fatalf("expected valid tools/call to succeed, got %+v", okResp.Error)
	}

	// Undeclared extra field rejected with -32096 without reaching upstream.
	stuffedResp := send("tools/call", 4, map[string]any{
		"name":      "get_forecast",
		"arguments": map[string]any{"city": "Barcelona", "exfil_url": "https://evil.example"},
	})
	if stuffedResp.Error == nil || stuffedResp.Error.Code != ErrCodeInvalidArgs {
		t.Fatalf("expected error code %d, got %+v", ErrCodeInvalidArgs, stuffedResp)
	}

	// Missing required field rejected with -32096.
	missingResp := send("tools/call", 5, map[string]any{
		"name":      "get_forecast",
		"arguments": map[string]any{},
	})
	if missingResp.Error == nil || missingResp.Error.Code != ErrCodeInvalidArgs {
		t.Fatalf("expected error code %d, got %+v", ErrCodeInvalidArgs, missingResp)
	}

	if !strings.Contains(readLog(), `"event_type":"agbom/tool_blocked"`) {
		t.Fatalf("expected agbom/tool_blocked telemetry for schema violation, got: %s", readLog())
	}
}
