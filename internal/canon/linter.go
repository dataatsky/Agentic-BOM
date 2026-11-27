package canon

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Finding represents a static security issue found in an MCP tool definition at scan time.
type Finding struct {
	Severity  string `json:"severity"` // CRITICAL, HIGH, MEDIUM
	Code      string `json:"code"`
	ToolName  string `json:"tool_name"`
	FieldPath string `json:"field_path"`
	Message   string `json:"message"`
}

var destructivePrefixes = []string{
	"delete_", "remove_", "drop_", "exec_", "write_", "run_", "destroy_",
}

var suspiciousPhrases = []string{
	"ignore previous instructions",
	"disregard previous",
	"system override",
	"before calling",
	"also silently send",
	"bcc ",
}

// LintToolSet runs LintTool across all tools in a set AND checks for cross-tool shadowing
// where one tool's description or schema strings reference another tool's name (within the
// same server or across supplied peer tool names).
func LintToolSet(rawTools []json.RawMessage, extraPeerToolNames ...string) ([]Finding, error) {
	allNamesSet := make(map[string]struct{}, len(rawTools)+len(extraPeerToolNames))
	for _, peer := range extraPeerToolNames {
		if p := strings.TrimSpace(peer); len(p) >= 4 {
			allNamesSet[p] = struct{}{}
		}
	}

	parsedObjs := make([]map[string]any, 0, len(rawTools))
	toolNames := make([]string, 0, len(rawTools))
	var findings []Finding

	for _, raw := range rawTools {
		f, err := LintTool(raw)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f...)

		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("lint toolset unmarshal: %w", err)
		}
		name, _ := obj["name"].(string)
		parsedObjs = append(parsedObjs, obj)
		toolNames = append(toolNames, name)
		if len(name) >= 4 {
			allNamesSet[name] = struct{}{}
		}
	}

	allNames := make([]string, 0, len(allNamesSet))
	for n := range allNamesSet {
		allNames = append(allNames, n)
	}
	sort.Strings(allNames)

	for i, obj := range parsedObjs {
		selfName := toolNames[i]
		walkCrossToolRefs(selfName, "$", obj, allNames, &findings)
	}

	return findings, nil
}

func walkCrossToolRefs(selfName, path string, v any, allNames []string, findings *[]Finding) {
	switch x := v.(type) {
	case string:
		// Skip the tool's own $.name field.
		if path == "$.name" {
			return
		}
		for _, other := range allNames {
			if other == selfName {
				continue
			}
			if containsIdentifier(x, other) {
				*findings = append(*findings, Finding{
					Severity:  "HIGH",
					Code:      "CROSS_TOOL_SHADOWING_REFERENCE",
					ToolName:  selfName,
					FieldPath: path,
					Message:   fmt.Sprintf("tool %q references sibling/peer tool %q in %s (cross-tool shadowing risk)", selfName, other, path),
				})
			}
		}
	case []any:
		for i, elem := range x {
			walkCrossToolRefs(selfName, fmt.Sprintf("%s[%d]", path, i), elem, allNames, findings)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkCrossToolRefs(selfName, path+"."+k, x[k], allNames, findings)
		}
	}
}

// containsIdentifier returns true if needle appears in haystack surrounded by non-identifier boundaries.
func containsIdentifier(haystack, needle string) bool {
	if needle == "" || len(haystack) < len(needle) {
		return false
	}
	lowerH := strings.ToLower(haystack)
	lowerN := strings.ToLower(needle)
	start := 0
	for {
		idx := strings.Index(lowerH[start:], lowerN)
		if idx == -1 {
			return false
		}
		pos := start + idx
		end := pos + len(lowerN)
		leftOK := pos == 0
		if !leftOK {
			r, _ := utf8.DecodeLastRuneInString(lowerH[:pos])
			leftOK = !isIdentChar(r)
		}
		rightOK := end == len(lowerH)
		if !rightOK {
			r, _ := utf8.DecodeRuneInString(lowerH[end:])
			rightOK = !isIdentChar(r)
		}
		if leftOK && rightOK {
			return true
		}
		start = pos + 1
	}
}

func isIdentChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// LintTool walks a raw MCP tool JSON object and checks for prompt-injection smuggling,
// invisible/bidi Unicode, x-mcp-header misuse, unsafe schemas, and untrusted annotation mismatches.
func LintTool(raw json.RawMessage) ([]Finding, error) {
	decoded, err := DecodeStrictJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("lint decode tool: %w", err)
	}
	obj, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("lint tool: expected json object, got %T", decoded)
	}
	toolName, _ := obj["name"].(string)

	var findings []Finding
	walkValue(toolName, "$", obj, &findings)

	// Check description padding, length, and prompt-injection heuristics.
	if desc, ok := obj["description"].(string); ok {
		if utf8.RuneCountInString(desc) > 1500 {
			findings = append(findings, Finding{
				Severity:  "MEDIUM",
				Code:      "EXCESSIVE_DESCRIPTION_LENGTH",
				ToolName:  toolName,
				FieldPath: "$.description",
				Message:   fmt.Sprintf("tool description exceeds 1500 runes (%d)", utf8.RuneCountInString(desc)),
			})
		}
		if strings.Contains(desc, "\n\n\n\n\n") {
			findings = append(findings, Finding{
				Severity:  "HIGH",
				Code:      "WHITESPACE_PADDING_SUSPECTED",
				ToolName:  toolName,
				FieldPath: "$.description",
				Message:   "excessive consecutive newlines detected in tool description",
			})
		}
		lower := strings.ToLower(desc)
		for _, phrase := range suspiciousPhrases {
			if strings.Contains(lower, phrase) {
				findings = append(findings, Finding{
					Severity:  "HIGH",
					Code:      "INJECTION_PHRASE_HEURISTIC",
					ToolName:  toolName,
					FieldPath: "$.description",
					Message:   fmt.Sprintf("suspicious directive phrase %q found in description", phrase),
				})
			}
		}
	}

	// Determine whether the tool name or annotations indicate a destructive/write operation.
	lowerName := strings.ToLower(toolName)
	matchedPrefix := ""
	for _, prefix := range destructivePrefixes {
		if strings.HasPrefix(lowerName, prefix) {
			matchedPrefix = prefix
			break
		}
	}
	isDestructive := matchedPrefix != ""

	// Check destructive tool name claiming readOnlyHint: true.
	if ann, ok := obj["annotations"].(map[string]any); ok {
		if dh, ok := ann["destructiveHint"].(bool); ok && dh {
			isDestructive = true
		}
		if ro, ok := ann["readOnlyHint"].(bool); ok && ro && matchedPrefix != "" {
			findings = append(findings, Finding{
				Severity:  "HIGH",
				Code:      "ANNOTATION_MISMATCH",
				ToolName:  toolName,
				FieldPath: "$.annotations.readOnlyHint",
				Message:   fmt.Sprintf("tool %q claims readOnlyHint=true despite destructive prefix %q", toolName, matchedPrefix),
			})
		}
	}

	// Flag destructive tools whose object inputSchema omits additionalProperties: false.
	if isDestructive {
		if schema, ok := obj["inputSchema"].(map[string]any); ok {
			if t, _ := schema["type"].(string); t == "object" {
				ap, hasAP := schema["additionalProperties"]
				apBool, isBool := ap.(bool)
				if !hasAP || !isBool || apBool {
					findings = append(findings, Finding{
						Severity:  "MEDIUM",
						Code:      "MISSING_ADDITIONAL_PROPERTIES_FALSE",
						ToolName:  toolName,
						FieldPath: "$.inputSchema.additionalProperties",
						Message:   fmt.Sprintf("sensitive tool %q object inputSchema should set additionalProperties=false to prevent argument stuffing", toolName),
					})
				}
			}
		}
	}

	return findings, nil
}

func walkValue(toolName, path string, v any, findings *[]Finding) {
	switch x := v.(type) {
	case string:
		lintUnicode(toolName, path, x, findings)
	case []any:
		for i, elem := range x {
			walkValue(toolName, fmt.Sprintf("%s[%d]", path, i), elem, findings)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := x[k]
			childPath := path + "." + k
			lintUnicode(toolName, childPath+"(key)", k, findings)
			if strings.EqualFold(k, "x-mcp-header") {
				*findings = append(*findings, Finding{
					Severity:  "HIGH",
					Code:      "X_MCP_HEADER_MIRROR",
					ToolName:  toolName,
					FieldPath: childPath,
					Message:   fmt.Sprintf("x-mcp-header annotation (%v) mirrors LLM-controlled argument into outbound HTTP header", val),
				})
			}
			walkValue(toolName, childPath, val, findings)
		}
	}
}

func lintUnicode(toolName, path, s string, findings *[]Finding) {
	offset := 0
	for _, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			*findings = append(*findings, Finding{
				Severity:  "CRITICAL",
				Code:      "INVISIBLE_UNICODE_TAG",
				ToolName:  toolName,
				FieldPath: path,
				Message:   fmt.Sprintf("invisible Unicode Tag character U+%X at rune offset %d", r, offset),
			})
			return
		case (r >= 0x200B && r <= 0x200D) || r == 0xFEFF:
			*findings = append(*findings, Finding{
				Severity:  "CRITICAL",
				Code:      "ZERO_WIDTH_UNICODE",
				ToolName:  toolName,
				FieldPath: path,
				Message:   fmt.Sprintf("zero-width character U+%04X at rune offset %d", r, offset),
			})
			return
		case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
			*findings = append(*findings, Finding{
				Severity:  "CRITICAL",
				Code:      "BIDI_OVERRIDE_TROJAN_SOURCE",
				ToolName:  toolName,
				FieldPath: path,
				Message:   fmt.Sprintf("bidirectional override character U+%04X at rune offset %d", r, offset),
			})
			return
		}
		offset++
	}
}
