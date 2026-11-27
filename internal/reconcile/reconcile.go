package reconcile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/secops/agbom-gate/internal/bom"
)

// Observation represents a single normalized runtime telemetry record extracted from
// either OWASP ACS NDJSON logs or OTLP/HTTP JSON trace exports.
type Observation struct {
	EventType    string
	ServerName   string
	ToolName     string
	DataStore    string
	ObservedHash string
	DriftedTools []string
	Reason       string
}

// Finding represents a discrepancy between live runtime telemetry and the declared signed AgBOM.
type Finding struct {
	Severity string // CRITICAL, HIGH, MEDIUM
	Code     string
	Target   string
	Details  string
}

// Result summarizes runtime-to-declared reconciliation.
type Result struct {
	ExitCode     int // 0 = clean, 2 = shadow capability or runtime drift detected
	Observations int
	Findings     []Finding
	Markdown     string
}

// ParseTelemetry decodes runtime observations from either OWASP ACS NDJSON logs
// or OTLP/HTTP JSON trace exports (single JSON document, JSON array, or NDJSON).
func ParseTelemetry(raw []byte) ([]Observation, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}

	// Try whole-document OTLP JSON array first.
	if trimmed[0] == '[' {
		var docs []json.RawMessage
		if err := json.Unmarshal(trimmed, &docs); err == nil {
			var all []Observation
			for _, d := range docs {
				obs, err := parseSingleRecord(d)
				if err != nil {
					return nil, err
				}
				all = append(all, obs...)
			}
			return all, nil
		}
	}

	// Try single multi-line OTLP/ACS JSON object.
	if trimmed[0] == '{' && json.Valid(trimmed) {
		return parseSingleRecord(trimmed)
	}

	// Otherwise parse line-delimited JSON (NDJSON).
	var all []Observation
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		obs, err := parseSingleRecord(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		all = append(all, obs...)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return all, nil
}

func parseSingleRecord(raw []byte) ([]Observation, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("invalid telemetry json: %w", err)
	}

	// OTLP ExportTraceServiceRequest format
	if _, isOTLP := probe["resourceSpans"]; isOTLP {
		return parseOTLPBatch(raw)
	}

	// OWASP ACS NDJSON or generic gateway log record
	var rec struct {
		EventType    string   `json:"event_type"`
		ServerName   string   `json:"server_name"`
		ToolName     string   `json:"tool_name"`
		DataStore    string   `json:"data_store"`
		ObservedHash string   `json:"observed_hash"`
		DriftedTools []string `json:"drifted_tools"`
		Reason       string   `json:"reason"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if rec.ServerName == "" && rec.ToolName == "" && rec.DataStore == "" && rec.EventType == "" {
		return nil, nil
	}
	return []Observation{{
		EventType:    rec.EventType,
		ServerName:   rec.ServerName,
		ToolName:     rec.ToolName,
		DataStore:    rec.DataStore,
		ObservedHash: rec.ObservedHash,
		DriftedTools: rec.DriftedTools,
		Reason:       rec.Reason,
	}}, nil
}

func parseOTLPBatch(raw []byte) ([]Observation, error) {
	var batch struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []struct {
					Name       string `json:"name"`
					Attributes []struct {
						Key   string `json:"key"`
						Value struct {
							StringValue string `json:"stringValue"`
							ArrayValue  *struct {
								Values []struct {
									StringValue string `json:"stringValue"`
								} `json:"values"`
							} `json:"arrayValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil {
		return nil, fmt.Errorf("decode otlp trace batch: %w", err)
	}

	var out []Observation
	for _, rs := range batch.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				obs := Observation{EventType: sp.Name}
				for _, attr := range sp.Attributes {
					switch attr.Key {
					case "agbom.event.type":
						if attr.Value.StringValue != "" {
							obs.EventType = attr.Value.StringValue
						}
					case "agbom.server.name":
						obs.ServerName = attr.Value.StringValue
					case "agbom.tool.name":
						obs.ToolName = attr.Value.StringValue
					case "agbom.data.store":
						obs.DataStore = attr.Value.StringValue
					case "agbom.tools_list.observed_sha256":
						obs.ObservedHash = attr.Value.StringValue
					case "agbom.event.reason":
						obs.Reason = attr.Value.StringValue
					case "agbom.drift.tools":
						if attr.Value.ArrayValue != nil {
							for _, v := range attr.Value.ArrayValue.Values {
								if v.StringValue != "" {
									obs.DriftedTools = append(obs.DriftedTools, v.StringValue)
								}
							}
						}
					}
				}
				if obs.ServerName != "" || obs.DataStore != "" || obs.ToolName != "" {
					out = append(out, obs)
				}
			}
		}
	}
	return out, nil
}

// Reconcile compares runtime observations against the declared CycloneDX 1.6 AgBOM,
// flagging shadow MCP servers, shadow data stores, undeclared tool invocations,
// hash mismatches, and quarantine events.
func Reconcile(declared *bom.BOM, observations []Observation) Result {
	declaredSvcs := map[string]*bom.Component{}
	declaredStores := map[string]*bom.Component{}
	for i := range declared.Components {
		c := &declared.Components[i]
		switch c.Type {
		case "service":
			declaredSvcs[c.Name] = c
		case "data":
			declaredStores[c.Name] = c
		}
	}

	seenFindings := map[string]struct{}{}
	var findings []Finding
	addFinding := func(f Finding) {
		key := f.Code + "|" + f.Target + "|" + f.Details
		if _, dup := seenFindings[key]; dup {
			return
		}
		seenFindings[key] = struct{}{}
		findings = append(findings, f)
	}

	for _, obs := range observations {
		// 1. Shadow Data Store check
		if obs.DataStore != "" {
			if _, ok := declaredStores[obs.DataStore]; !ok {
				addFinding(Finding{
					Severity: "CRITICAL",
					Code:     "SHADOW_DATA_STORE",
					Target:   obs.DataStore,
					Details:  fmt.Sprintf("Undeclared RAG/memory data store %q observed in runtime telemetry", obs.DataStore),
				})
			}
		}

		// 2. Shadow MCP Server check
		if obs.ServerName != "" {
			svc, declaredOK := declaredSvcs[obs.ServerName]
			if !declaredOK {
				addFinding(Finding{
					Severity: "CRITICAL",
					Code:     "SHADOW_MCP_SERVER",
					Target:   obs.ServerName,
					Details:  fmt.Sprintf("Undeclared MCP server/sub-agent %q observed in runtime traffic (absent from signed AgBOM)", obs.ServerName),
				})
				continue
			}

			// 3. Quarantine event observed
			if obs.EventType == "agbom/quarantined" {
				detail := "Runtime quarantine triggered"
				if len(obs.DriftedTools) > 0 {
					detail = fmt.Sprintf("Runtime quarantine triggered (drifted tools: %s)", strings.Join(obs.DriftedTools, ", "))
				}
				addFinding(Finding{
					Severity: "CRITICAL",
					Code:     "QUARANTINE_EVENT_OBSERVED",
					Target:   obs.ServerName,
					Details:  detail,
				})
			}

			// 4. Runtime tools_list_sha256 drift check
			if obs.ObservedHash != "" {
				expectedHash, _ := svc.GetProperty(bom.PropToolsListSHA256)
				if expectedHash != "" && obs.ObservedHash != expectedHash {
					addFinding(Finding{
						Severity: "CRITICAL",
						Code:     "RUNTIME_HASH_DRIFT",
						Target:   obs.ServerName,
						Details:  fmt.Sprintf("Observed tools_list_sha256 %s differs from declared AgBOM hash %s", shortHash(obs.ObservedHash), shortHash(expectedHash)),
					})
				}
			}

			// 5. Undeclared tool invocation check (fail-closed: empty allowed_tools permits 0 tools unless '*').
			if obs.ToolName != "" {
				allowedVal, _ := svc.GetProperty(bom.PropAllowedTools)
				if strings.TrimSpace(allowedVal) != "*" {
					allowed := bom.ParseCSVProperty(allowedVal)
					if _, ok := allowed[obs.ToolName]; !ok {
						addFinding(Finding{
							Severity: "HIGH",
							Code:     "UNDECLARED_TOOL_CALL",
							Target:   obs.ServerName + ":" + obs.ToolName,
							Details:  fmt.Sprintf("Tool %q observed on %q is not in declared agbom:allowed_tools", obs.ToolName, obs.ServerName),
						})
					}
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Target < findings[j].Target
	})

	exitCode := 0
	if len(findings) > 0 {
		exitCode = 2
	}
	return Result{
		ExitCode:     exitCode,
		Observations: len(observations),
		Findings:     findings,
		Markdown:     renderMarkdown(findings, len(observations), exitCode),
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func renderMarkdown(findings []Finding, obsCount, exitCode int) string {
	var b strings.Builder
	if exitCode == 0 {
		fmt.Fprintf(&b, "## agbom-gate Runtime Reconciliation: PASS\n\nReconciled %d runtime telemetry observation(s) against signed AgBOM. No shadow capabilities or hash drift detected.\n", obsCount)
		return b.String()
	}
	fmt.Fprintf(&b, "## agbom-gate Runtime Reconciliation: SHADOW CAPABILITY / DRIFT DETECTED\n\nReconciled %d runtime telemetry observation(s).\n\n", obsCount)
	b.WriteString("| Severity | Target | Code | Details |\n")
	b.WriteString("| :--- | :--- | :--- | :--- |\n")
	for _, f := range findings {
		fmt.Fprintf(&b, "| **%s** | `%s` | `%s` | %s |\n", f.Severity, f.Target, f.Code, f.Details)
	}
	return b.String()
}
