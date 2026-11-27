package bom

import (
	"encoding/json"
	"strings"

	"github.com/secops/agbom-gate/internal/canon"
)

const (
	PropProtocol           = "agbom:protocol"
	PropTransport          = "agbom:transport"
	PropAllowedTools       = "agbom:allowed_tools"
	PropStepUpTools        = "agbom:step_up_approval_tools"
	PropToolsListSHA256    = "agbom:tools_list_sha256"
	PropToolPinsJSON       = "agbom:tool_pins_json"
	PropTokenPassthru      = "agbom:token_passthrough"
	PropOwner              = "agbom:owner"
	PropNHIPrincipal       = "agbom:nhi_principal"
	PropAutonomyTier       = "agbom:autonomy_tier"
	PropSystemPromptSHA256 = "agbom:system_prompt_sha256"
	PropA2ACardSHA256      = "agbom:a2a_card_sha256"
	PropA2AJWSStatus       = "agbom:a2a_jws_status"
	PropSourceFile         = "agbom:source_file"
	PropEndpoint           = "agbom:endpoint"
	PropStoreType          = "agbom:store_type"
	PropAccessMode         = "agbom:access_mode"
	PropDataClassification = "agbom:data_classification"
)

type BOM struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    Metadata    `json:"metadata"`
	Components  []Component `json:"components"`
}

type Metadata struct {
	Timestamp  string     `json:"timestamp,omitempty"`
	Component  *Component `json:"component,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GetMetadataProperty returns the value of the first matching top-level metadata property.
func (b *BOM) GetMetadataProperty(name string) (string, bool) {
	if b == nil {
		return "", false
	}
	for _, p := range b.Metadata.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// GetProperty returns the value of the first matching property name.
func (c *Component) GetProperty(name string) (string, bool) {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// SetProperty sets or updates a property on the component.
func (c *Component) SetProperty(name, value string) {
	for i := range c.Properties {
		if c.Properties[i].Name == name {
			c.Properties[i].Value = value
			return
		}
	}
	c.Properties = append(c.Properties, Property{Name: name, Value: value})
}

// ParseCSVProperty splits a comma-separated property into a set of trimmed non-empty strings.
func ParseCSVProperty(val string) map[string]struct{} {
	res := make(map[string]struct{})
	for _, part := range strings.Split(val, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			res[p] = struct{}{}
		}
	}
	return res
}

// FindMCPService locates an MCP service component by name.
func (b *BOM) FindMCPService(name string) *Component {
	for i := range b.Components {
		if b.Components[i].Type == "service" && b.Components[i].Name == name {
			return &b.Components[i]
		}
	}
	return nil
}

// ToolPins decodes agbom:tool_pins_json from a service component if present.
func (c *Component) ToolPins() ([]canon.ToolPin, error) {
	raw, ok := c.GetProperty(PropToolPinsJSON)
	if !ok || raw == "" {
		return nil, nil
	}
	var pins []canon.ToolPin
	if err := json.Unmarshal([]byte(raw), &pins); err != nil {
		return nil, err
	}
	return pins, nil
}
