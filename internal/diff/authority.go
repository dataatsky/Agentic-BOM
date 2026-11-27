package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/secops/agbom-gate/internal/bom"
	"github.com/secops/agbom-gate/internal/canon"
)

type Change struct {
	Severity string // CRITICAL, HIGH, MEDIUM, INFO
	Server   string
	Code     string
	Summary  string
}

type Result struct {
	ExitCode int // 0 = pass, 2 = security review required
	Changes  []Change
	Markdown string
}

// Compare evaluates authority and integrity drift between a base AgBOM and a PR head AgBOM.
func Compare(base, head *bom.BOM) Result {
	baseSvcs := map[string]*bom.Component{}
	baseModels := map[string]*bom.Component{}
	baseData := map[string]*bom.Component{}
	for i := range base.Components {
		c := &base.Components[i]
		switch c.Type {
		case "service":
			baseSvcs[c.Name] = c
		case "machine-learning-model":
			baseModels[c.Name] = c
		case "data":
			baseData[c.Name] = c
		}
	}
	headSvcs := map[string]*bom.Component{}
	headModels := map[string]*bom.Component{}
	headData := map[string]*bom.Component{}
	for i := range head.Components {
		c := &head.Components[i]
		switch c.Type {
		case "service":
			headSvcs[c.Name] = c
		case "machine-learning-model":
			headModels[c.Name] = c
		case "data":
			headData[c.Name] = c
		}
	}

	var changes []Change

	// Compare service components (MCP servers & A2A peer agents).
	for _, name := range sortedUnionKeys(baseSvcs, headSvcs) {
		bSvc, inBase := baseSvcs[name]
		hSvc, inHead := headSvcs[name]

		if !inBase && inHead {
			code := "NEW_MCP_SERVER"
			summary := fmt.Sprintf("New MCP service %q added to AgBOM", name)
			if proto, _ := hSvc.GetProperty(bom.PropProtocol); strings.HasPrefix(proto, "a2a/") {
				code = "NEW_A2A_AGENT"
				summary = fmt.Sprintf("New A2A peer agent %q added to AgBOM", name)
			}
			changes = append(changes, Change{
				Severity: "HIGH",
				Server:   name,
				Code:     code,
				Summary:  summary,
			})
			continue
		}
		if inBase && !inHead {
			changes = append(changes, Change{
				Severity: "INFO",
				Server:   name,
				Code:     "REMOVED_MCP_SERVER",
				Summary:  fmt.Sprintf("Service %q removed from AgBOM", name),
			})
			continue
		}

		// 1. Check composite tools_list_sha256 drift and per-tool write-capability escalations.
		bPins, _ := bSvc.ToolPins()
		hPins, _ := hSvc.ToolPins()
		bHash, _ := bSvc.GetProperty(bom.PropToolsListSHA256)
		hHash, _ := hSvc.GetProperty(bom.PropToolsListSHA256)
		if bHash != hHash {
			drifted := canon.DiffPins(bPins, hPins)
			detail := "composite hash changed"
			if len(drifted) > 0 {
				detail = fmt.Sprintf("mutated/changed tools: %s", strings.Join(drifted, ", "))
			}
			changes = append(changes, Change{
				Severity: "HIGH",
				Server:   name,
				Code:     "TOOLS_HASH_DRIFT",
				Summary:  fmt.Sprintf("tools_list_sha256 changed (%s)", detail),
			})
		}
		if escalated := detectWriteCapabilityEscalations(bPins, hPins); len(escalated) > 0 {
			changes = append(changes, Change{
				Severity: "HIGH",
				Server:   name,
				Code:     "WRITE_CAPABILITY_ESCALATION",
				Summary:  fmt.Sprintf("Tool annotation escalated write/destructive capability: %s", strings.Join(escalated, ", ")),
			})
		}

		// 2. Check allowed_tools expansion (including wildcard '*').
		bAllowedVal, _ := bSvc.GetProperty(bom.PropAllowedTools)
		hAllowedVal, _ := hSvc.GetProperty(bom.PropAllowedTools)
		if strings.TrimSpace(hAllowedVal) == "*" && strings.TrimSpace(bAllowedVal) != "*" {
			changes = append(changes, Change{
				Severity: "CRITICAL",
				Server:   name,
				Code:     "WILDCARD_AUTHORITY_GRANTED",
				Summary:  "agbom:allowed_tools escalated to unrestricted wildcard '*'",
			})
		} else if strings.TrimSpace(hAllowedVal) != "*" {
			bAllowed := bom.ParseCSVProperty(bAllowedVal)
			hAllowed := bom.ParseCSVProperty(hAllowedVal)
			var addedTools []string
			for t := range hAllowed {
				if _, ok := bAllowed[t]; !ok {
					addedTools = append(addedTools, t)
				}
			}
			sort.Strings(addedTools)
			if len(addedTools) > 0 {
				changes = append(changes, Change{
					Severity: "HIGH",
					Server:   name,
					Code:     "AUTHORITY_EXPANSION",
					Summary:  fmt.Sprintf("New tools added to allowed_tools: %s", strings.Join(addedTools, ", ")),
				})
			}
		}

		// 3. Check HITL step_up_approval_tools downgrade.
		bStepVal, _ := bSvc.GetProperty(bom.PropStepUpTools)
		hStepVal, _ := hSvc.GetProperty(bom.PropStepUpTools)
		bStep := bom.ParseCSVProperty(bStepVal)
		hStep := bom.ParseCSVProperty(hStepVal)
		var removedGates []string
		for t := range bStep {
			if _, ok := hStep[t]; !ok {
				removedGates = append(removedGates, t)
			}
		}
		sort.Strings(removedGates)
		if len(removedGates) > 0 {
			changes = append(changes, Change{
				Severity: "CRITICAL",
				Server:   name,
				Code:     "HITL_GATE_REMOVED",
				Summary:  fmt.Sprintf("Human-in-the-loop step-up approval removed for: %s", strings.Join(removedGates, ", ")),
			})
		}

		// 4. Check token passthrough regression.
		bPT, _ := bSvc.GetProperty(bom.PropTokenPassthru)
		hPT, hasHPT := hSvc.GetProperty(bom.PropTokenPassthru)
		if hasHPT && hPT != bPT && !strings.HasPrefix(strings.ToLower(hPT), "forbidden") {
			changes = append(changes, Change{
				Severity: "CRITICAL",
				Server:   name,
				Code:     "TOKEN_PASSTHROUGH_ENABLED",
				Summary:  fmt.Sprintf("agbom:token_passthrough changed from %q to %q", bPT, hPT),
			})
		}

		// 5. Check A2A Agent Card hash drift & JWS verification downgrades.
		bCardHash, _ := bSvc.GetProperty(bom.PropA2ACardSHA256)
		hCardHash, _ := hSvc.GetProperty(bom.PropA2ACardSHA256)
		if bCardHash != hCardHash {
			changes = append(changes, Change{
				Severity: "HIGH",
				Server:   name,
				Code:     "A2A_CARD_DRIFT",
				Summary:  fmt.Sprintf("A2A Agent Card canonical SHA-256 changed (%s -> %s)", shortHash(bCardHash), shortHash(hCardHash)),
			})
		}
		bJWS, _ := bSvc.GetProperty(bom.PropA2AJWSStatus)
		hJWS, _ := hSvc.GetProperty(bom.PropA2AJWSStatus)
		if (bJWS == "verified" && hJWS != "verified") || (hJWS == "invalid" && bJWS != "invalid") {
			changes = append(changes, Change{
				Severity: "CRITICAL",
				Server:   name,
				Code:     "A2A_SIGNATURE_DOWNGRADE",
				Summary:  fmt.Sprintf("A2A Agent Card JWS status degraded from %q to %q", bJWS, hJWS),
			})
		}
	}

	// Compare RAG / memory data stores (type: "data").
	for _, name := range sortedUnionKeys(baseData, headData) {
		bStore, inBase := baseData[name]
		hStore, inHead := headData[name]
		if !inBase && inHead {
			mode, _ := hStore.GetProperty(bom.PropAccessMode)
			sev := "MEDIUM"
			if isWritableAccessMode(mode) {
				sev = "HIGH"
			}
			changes = append(changes, Change{
				Severity: sev,
				Server:   name,
				Code:     "NEW_DATA_STORE",
				Summary:  fmt.Sprintf("New data store %q added (access_mode=%q)", name, mode),
			})
			continue
		}
		if inBase && !inHead {
			continue
		}
		bMode, _ := bStore.GetProperty(bom.PropAccessMode)
		hMode, _ := hStore.GetProperty(bom.PropAccessMode)
		if !isWritableAccessMode(bMode) && isWritableAccessMode(hMode) {
			changes = append(changes, Change{
				Severity: "CRITICAL",
				Server:   name,
				Code:     "DATA_ACCESS_ESCALATION",
				Summary:  fmt.Sprintf("Data store %q access_mode escalated from %q to %q", name, bMode, hMode),
			})
		}
	}

	// Compare machine-learning-model / system prompt hashes.
	for _, name := range sortedUnionKeys(baseModels, headModels) {
		bMod, inBase := baseModels[name]
		hMod, inHead := headModels[name]
		if !inBase && inHead {
			changes = append(changes, Change{
				Severity: "MEDIUM",
				Server:   name,
				Code:     "NEW_SYSTEM_PROMPT",
				Summary:  fmt.Sprintf("New system prompt / model component %q added to AgBOM", name),
			})
			continue
		}
		if inBase && !inHead {
			continue
		}
		bPrompt, _ := bMod.GetProperty(bom.PropSystemPromptSHA256)
		hPrompt, _ := hMod.GetProperty(bom.PropSystemPromptSHA256)
		if bPrompt != hPrompt {
			changes = append(changes, Change{
				Severity: "HIGH",
				Server:   name,
				Code:     "SYSTEM_PROMPT_DRIFT",
				Summary:  fmt.Sprintf("agbom:system_prompt_sha256 changed (%s -> %s)", shortHash(bPrompt), shortHash(hPrompt)),
			})
		}
	}

	exitCode := 0
	for _, c := range changes {
		if c.Severity == "CRITICAL" || c.Severity == "HIGH" || c.Severity == "MEDIUM" {
			exitCode = 2
			break
		}
	}

	return Result{
		ExitCode: exitCode,
		Changes:  changes,
		Markdown: renderMarkdown(changes, exitCode),
	}
}

func detectWriteCapabilityEscalations(basePins, headPins []canon.ToolPin) []string {
	baseMap := make(map[string]canon.ToolPin, len(basePins))
	for _, p := range basePins {
		baseMap[p.Name] = p
	}
	var out []string
	for _, hp := range headPins {
		bp, ok := baseMap[hp.Name]
		if !ok {
			continue
		}
		roFlipped := bp.ReadOnlyHint != nil && *bp.ReadOnlyHint && (hp.ReadOnlyHint == nil || !*hp.ReadOnlyHint)
		destFlipped := (bp.DestructiveHint == nil || !*bp.DestructiveHint) && hp.DestructiveHint != nil && *hp.DestructiveHint
		if roFlipped && destFlipped {
			out = append(out, fmt.Sprintf("%s (readOnlyHint=false, destructiveHint=true)", hp.Name))
		} else if roFlipped {
			out = append(out, fmt.Sprintf("%s (readOnlyHint true->false)", hp.Name))
		} else if destFlipped {
			out = append(out, fmt.Sprintf("%s (destructiveHint->true)", hp.Name))
		}
	}
	sort.Strings(out)
	return out
}

func isWritableAccessMode(mode string) bool {
	m := strings.ToLower(strings.TrimSpace(mode))
	return strings.Contains(m, "write") || m == "admin" || m == "rw"
}

func sortedUnionKeys(a, b map[string]*bom.Component) []string {
	m := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		m[k] = struct{}{}
	}
	for k := range b {
		m[k] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	if h == "" {
		return "<none>"
	}
	return h
}

func renderMarkdown(changes []Change, exitCode int) string {
	var b strings.Builder
	if exitCode == 0 {
		b.WriteString("## agbom-gate Authority Diff: PASS\n\nNo authority expansion, tool hash drift, or HITL gate downgrades detected.\n")
		return b.String()
	}
	b.WriteString("## agbom-gate Authority Diff: SECURITY REVIEW REQUIRED\n\n")
	b.WriteString("| Severity | Server | Code | Details |\n")
	b.WriteString("| :--- | :--- | :--- | :--- |\n")
	for _, c := range changes {
		fmt.Fprintf(&b, "| **%s** | `%s` | `%s` | %s |\n", c.Severity, c.Server, c.Code, c.Summary)
	}
	return b.String()
}
