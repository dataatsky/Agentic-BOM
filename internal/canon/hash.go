package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ToolPin stores the RFC 8785 canonical SHA-256 digest of a single MCP tool definition,
// along with optional annotation metadata used by the PR authority diff engine.
type ToolPin struct {
	Name            string `json:"name"`
	SHA256          string `json:"sha256"`
	ReadOnlyHint    *bool  `json:"read_only_hint,omitempty"`
	DestructiveHint *bool  `json:"destructive_hint,omitempty"`
}

// HashToolSet canonicalizes all tools from an aggregated tools/list response,
// rejecting missing or duplicate tool names, and returns the composite server hash
// along with per-tool hashes sorted deterministically by exact UTF-8 byte order of tool name.
func HashToolSet(rawTools []json.RawMessage) (string, []ToolPin, error) {
	seen := make(map[string]struct{}, len(rawTools))
	pins := make([]ToolPin, 0, len(rawTools))

	for _, raw := range rawTools {
		var envelope struct {
			Name        string `json:"name"`
			Annotations *struct {
				ReadOnlyHint    *bool `json:"readOnlyHint"`
				DestructiveHint *bool `json:"destructiveHint"`
			} `json:"annotations"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return "", nil, fmt.Errorf("invalid tool json: %w", err)
		}
		if envelope.Name == "" {
			return "", nil, errors.New("tool missing required name field")
		}
		if _, dup := seen[envelope.Name]; dup {
			return "", nil, fmt.Errorf("duplicate tool name detected: %s", envelope.Name)
		}
		seen[envelope.Name] = struct{}{}

		// Preserve all fields inside the tool object (including unknown/_meta fields)
		// so attackers cannot smuggle instructions via unmodeled keys.
		jcsBytes, err := JCS(raw)
		if err != nil {
			return "", nil, fmt.Errorf("jcs transform failed for %s: %w", envelope.Name, err)
		}

		sum := sha256.Sum256(jcsBytes)
		pin := ToolPin{
			Name:   envelope.Name,
			SHA256: hex.EncodeToString(sum[:]),
		}
		if envelope.Annotations != nil {
			pin.ReadOnlyHint = envelope.Annotations.ReadOnlyHint
			pin.DestructiveHint = envelope.Annotations.DestructiveHint
		}
		pins = append(pins, pin)
	}

	sort.Slice(pins, func(i, j int) bool {
		return pins[i].Name < pins[j].Name
	})

	var b strings.Builder
	for i, p := range pins {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p.Name)
		b.WriteByte(':')
		b.WriteString(p.SHA256)
	}

	compSum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(compSum[:]), pins, nil
}

// DiffPins returns sorted tool names whose hash changed, was added, or was removed.
func DiffPins(expected, observed []ToolPin) []string {
	expMap := make(map[string]string, len(expected))
	for _, p := range expected {
		expMap[p.Name] = p.SHA256
	}
	obsMap := make(map[string]string, len(observed))
	for _, p := range observed {
		obsMap[p.Name] = p.SHA256
	}

	drifted := make([]string, 0)
	for name, eh := range expMap {
		if oh, ok := obsMap[name]; !ok || oh != eh {
			drifted = append(drifted, name)
		}
	}
	for name := range obsMap {
		if _, ok := expMap[name]; !ok {
			drifted = append(drifted, name)
		}
	}
	sort.Strings(drifted)
	return drifted
}
