package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/secops/agbom-gate/internal/canon"
)

// ApprovalRequest is sent to an external HITL step-up approval hook when a tool listed
// in agbom:step_up_approval_tools is invoked.
type ApprovalRequest struct {
	ServerName   string          `json:"server_name"`
	ToolName     string          `json:"tool_name"`
	Arguments    json.RawMessage `json:"arguments,omitempty"`
	NHIPrincipal string          `json:"nhi_principal,omitempty"`
	TraceParent  string          `json:"traceparent,omitempty"`
}

// ApprovalResponse is returned by an external HITL step-up approval hook.
type ApprovalResponse struct {
	Approved bool   `json:"approved"`
	Approver string `json:"approver,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// ApprovalHook decides whether a step-up-gated tool call is approved by a human/policy engine.
type ApprovalHook func(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error)

// NewWebhookApprovalHook creates a fail-closed HTTP POST approval callback hook.
// Any transport error, non-2xx status, invalid JSON, or approved=false denies execution.
func NewWebhookApprovalHook(webhookURL string, client *http.Client) ApprovalHook {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return func(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error) {
		body, err := json.Marshal(req)
		if err != nil {
			return ApprovalResponse{}, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
		if err != nil {
			return ApprovalResponse{}, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if req.TraceParent != "" {
			httpReq.Header.Set("traceparent", req.TraceParent)
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			return ApprovalResponse{}, fmt.Errorf("approval webhook request failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return ApprovalResponse{}, fmt.Errorf("approval webhook returned HTTP %d", resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if err != nil {
			return ApprovalResponse{}, fmt.Errorf("read approval webhook response: %w", err)
		}
		var out ApprovalResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return ApprovalResponse{}, fmt.Errorf("decode approval webhook response: %w", err)
		}
		return out, nil
	}
}

var (
	reBearerSecret = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	reAPIKeySecret = regexp.MustCompile(`\b(?:sk-|ghp_|gho_|xoxb-|AKIA)[A-Za-z0-9_-]{8,}\b`)
	reEmailAddress = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

// redactText strips common secret/PII patterns and control characters before emitting DFIR snippets.
func redactText(s string, maxRunes int) string {
	cleaned := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s)
	cleaned = reBearerSecret.ReplaceAllString(cleaned, "Bearer [REDACTED]")
	cleaned = reAPIKeySecret.ReplaceAllString(cleaned, "[REDACTED_KEY]")
	cleaned = reEmailAddress.ReplaceAllString(cleaned, "[REDACTED_EMAIL]")
	cleaned = strings.TrimSpace(cleaned)
	runes := []rune(cleaned)
	if maxRunes > 0 && len(runes) > maxRunes {
		return string(runes[:maxRunes]) + "..."
	}
	return cleaned
}

// buildRedactedDriftSummary produces a compact, redacted DFIR summary of drifted tools
// including any static lint codes detected on the mutated definitions.
func buildRedactedDriftSummary(allTools []json.RawMessage, drifted []string) string {
	if len(drifted) == 0 {
		return ""
	}
	driftSet := make(map[string]struct{}, len(drifted))
	for _, d := range drifted {
		driftSet[d] = struct{}{}
	}
	byName := make(map[string]json.RawMessage, len(allTools))
	for _, raw := range allTools {
		var meta struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &meta) == nil && meta.Name != "" {
			byName[meta.Name] = raw
		}
	}

	var parts []string
	for _, name := range drifted {
		if _, ok := driftSet[name]; !ok {
			continue
		}
		raw, exists := byName[name]
		if !exists {
			parts = append(parts, fmt.Sprintf("%s: <removed from tools/list>", name))
			continue
		}
		var detail struct {
			Description string `json:"description"`
		}
		_ = json.Unmarshal(raw, &detail)
		findings, _ := canon.LintTool(raw)
		codeSet := map[string]struct{}{}
		var codes []string
		for _, f := range findings {
			if _, seen := codeSet[f.Code]; !seen {
				codeSet[f.Code] = struct{}{}
				codes = append(codes, f.Code)
			}
		}
		snippet := redactText(detail.Description, 160)
		if len(codes) > 0 {
			parts = append(parts, fmt.Sprintf("%s [%s]: %q", name, strings.Join(codes, ","), snippet))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %q", name, snippet))
		}
	}
	return strings.Join(parts, "; ")
}
