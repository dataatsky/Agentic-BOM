package diff

import (
	"strings"
	"testing"

	"github.com/secops/agbom-gate/internal/bom"
)

func makeTestBOM(hash, allowed, stepUp, pinsJSON string) *bom.BOM {
	return &bom.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []bom.Component{
			{
				Type: "service",
				Name: "jira-mcp",
				Properties: []bom.Property{
					{Name: bom.PropToolsListSHA256, Value: hash},
					{Name: bom.PropAllowedTools, Value: allowed},
					{Name: bom.PropStepUpTools, Value: stepUp},
					{Name: bom.PropToolPinsJSON, Value: pinsJSON},
				},
			},
		},
	}
}

func TestNoAuthorityChange(t *testing.T) {
	b := makeTestBOM("aaa", "get_ticket", "close_ticket", `[{"name":"get_ticket","sha256":"111"}]`)
	res := Compare(b, b)
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d (%s)", res.ExitCode, res.Markdown)
	}
}

func TestSilentDescriptionMutation(t *testing.T) {
	base := makeTestBOM("aaa", "get_ticket", "close_ticket", `[{"name":"get_ticket","sha256":"111"}]`)
	head := makeTestBOM("bbb", "get_ticket", "close_ticket", `[{"name":"get_ticket","sha256":"222"}]`)
	res := Compare(base, head)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2 on hash drift, got %d", res.ExitCode)
	}
	if !strings.Contains(res.Markdown, "get_ticket") {
		t.Fatalf("expected mutated tool name in diff markdown, got:\n%s", res.Markdown)
	}
}

func TestWriteCapabilityEscalationReadOnlyHintFlip(t *testing.T) {
	base := makeTestBOM("aaa", "get_ticket", "", `[{"name":"get_ticket","sha256":"111","read_only_hint":true}]`)
	head := makeTestBOM("bbb", "get_ticket", "", `[{"name":"get_ticket","sha256":"222","read_only_hint":false,"destructive_hint":true}]`)
	res := Compare(base, head)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2, got %d", res.ExitCode)
	}
	if !strings.Contains(res.Markdown, "WRITE_CAPABILITY_ESCALATION") {
		t.Fatalf("expected WRITE_CAPABILITY_ESCALATION in diff markdown, got:\n%s", res.Markdown)
	}
}

func TestDataStoreAccessEscalation(t *testing.T) {
	base := &bom.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []bom.Component{
			{
				Type: "data",
				Name: "ir-playbook-vector-store",
				Properties: []bom.Property{
					{Name: bom.PropStoreType, Value: "rag-knowledge"},
					{Name: bom.PropAccessMode, Value: "read-only"},
				},
			},
		},
	}
	head := &bom.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []bom.Component{
			{
				Type: "data",
				Name: "ir-playbook-vector-store",
				Properties: []bom.Property{
					{Name: bom.PropStoreType, Value: "rag-knowledge"},
					{Name: bom.PropAccessMode, Value: "read-write"},
				},
			},
		},
	}
	res := Compare(base, head)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2, got %d", res.ExitCode)
	}
	if !strings.Contains(res.Markdown, "DATA_ACCESS_ESCALATION") {
		t.Fatalf("expected DATA_ACCESS_ESCALATION in diff markdown, got:\n%s", res.Markdown)
	}
}

func TestAuthorityExpansion(t *testing.T) {
	base := makeTestBOM("aaa", "get_ticket", "close_ticket", "")
	head := makeTestBOM("aaa", "get_ticket,delete_ticket", "close_ticket", "")
	res := Compare(base, head)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2 on allowed_tools expansion, got %d", res.ExitCode)
	}
}

func TestHITLGateRemoved(t *testing.T) {
	base := makeTestBOM("aaa", "get_ticket,close_ticket", "close_ticket", "")
	head := makeTestBOM("aaa", "get_ticket,close_ticket", "", "")
	res := Compare(base, head)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2 on HITL gate removal, got %d", res.ExitCode)
	}
}

func TestNewMCPServerAdded(t *testing.T) {
	base := makeTestBOM("aaa", "get_ticket", "close_ticket", "")
	head := makeTestBOM("aaa", "get_ticket", "close_ticket", "")
	head.Components = append(head.Components, bom.Component{
		Type: "service",
		Name: "shadow-mcp",
		Properties: []bom.Property{
			{Name: bom.PropToolsListSHA256, Value: "ccc"},
		},
	})
	res := Compare(base, head)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2 when new MCP service is added, got %d", res.ExitCode)
	}
}

func TestSystemPromptAndA2ACardDrift(t *testing.T) {
	base := &bom.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []bom.Component{
			{
				Type: "machine-learning-model",
				Name: "prompt:prompts/system.md",
				Properties: []bom.Property{
					{Name: bom.PropSystemPromptSHA256, Value: "1111111111111111"},
				},
			},
			{
				Type: "service",
				Name: "triage-peer",
				Properties: []bom.Property{
					{Name: bom.PropProtocol, Value: "a2a/1.0"},
					{Name: bom.PropA2ACardSHA256, Value: "aaaa1111aaaa1111"},
					{Name: bom.PropA2AJWSStatus, Value: "verified"},
				},
			},
		},
	}
	head := &bom.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []bom.Component{
			{
				Type: "machine-learning-model",
				Name: "prompt:prompts/system.md",
				Properties: []bom.Property{
					{Name: bom.PropSystemPromptSHA256, Value: "2222222222222222"},
				},
			},
			{
				Type: "service",
				Name: "triage-peer",
				Properties: []bom.Property{
					{Name: bom.PropProtocol, Value: "a2a/1.0"},
					{Name: bom.PropA2ACardSHA256, Value: "bbbb2222bbbb2222"},
					{Name: bom.PropA2AJWSStatus, Value: "unsigned"},
				},
			},
		},
	}

	res := Compare(base, head)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2, got %d", res.ExitCode)
	}
	for _, want := range []string{"SYSTEM_PROMPT_DRIFT", "A2A_CARD_DRIFT", "A2A_SIGNATURE_DOWNGRADE"} {
		if !strings.Contains(res.Markdown, want) {
			t.Fatalf("expected %s in diff markdown, got:\n%s", want, res.Markdown)
		}
	}
}

func TestWildcardAuthorityEscalationBlocked(t *testing.T) {
	base := makeTestBOM("aaa", "get_ticket", "", "")
	head := makeTestBOM("aaa", "*", "", "")
	res := Compare(base, head)
	if res.ExitCode != 2 {
		t.Fatalf("expected exit 2 on wildcard allowed_tools escalation, got %d", res.ExitCode)
	}
	if !strings.Contains(res.Markdown, "WILDCARD_AUTHORITY_GRANTED") {
		t.Fatalf("expected WILDCARD_AUTHORITY_GRANTED in diff markdown, got:\n%s", res.Markdown)
	}
}
