package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/secops/agbom-gate/internal/canon"
)

// CompiledSchema validates MCP tool call params.arguments against a pinned JSON Schema
// (Draft-07 / 2020-12 core subset) without external dependencies.
type CompiledSchema struct {
	types                []string
	properties           map[string]*CompiledSchema
	required             []string
	hasAdditionalProps   bool
	allowAdditionalProps bool
	additionalPropSchema *CompiledSchema
	enumVals             [][]byte // canonical JCS representations
	hasConst             bool
	constVal             []byte
	minLength            *int
	maxLength            *int
	pattern              *regexp.Regexp
	minimum              *float64
	maximum              *float64
	exclusiveMin         *float64
	exclusiveMax         *float64
	multipleOf           *float64
	items                *CompiledSchema
	minItems             *int
	maxItems             *int
	uniqueItems          bool
	anyOf                []*CompiledSchema
	oneOf                []*CompiledSchema
	allOf                []*CompiledSchema
}

// CompileInputSchema parses a tool's raw inputSchema JSON into a CompiledSchema.
func CompileInputSchema(raw json.RawMessage) (*CompiledSchema, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var node any
	if err := dec.Decode(&node); err != nil {
		return nil, fmt.Errorf("decode inputSchema: %w", err)
	}
	return compileSchemaNode(node)
}

func compileSchemaNode(node any) (*CompiledSchema, error) {
	switch v := node.(type) {
	case bool:
		if v {
			return &CompiledSchema{}, nil
		}
		// Boolean schema "false" rejects every value.
		return &CompiledSchema{types: []string{"__never__"}}, nil
	case map[string]any:
		return compileSchemaObject(v)
	default:
		return nil, fmt.Errorf("schema must be object or boolean, got %T", node)
	}
}

func compileSchemaObject(obj map[string]any) (*CompiledSchema, error) {
	cs := &CompiledSchema{allowAdditionalProps: true}

	if t, ok := obj["type"]; ok {
		switch tv := t.(type) {
		case string:
			cs.types = []string{tv}
		case []any:
			for _, elem := range tv {
				if s, ok := elem.(string); ok {
					cs.types = append(cs.types, s)
				}
			}
		}
	}

	if props, ok := obj["properties"].(map[string]any); ok {
		cs.properties = make(map[string]*CompiledSchema, len(props))
		for k, v := range props {
			sub, err := compileSchemaNode(v)
			if err != nil {
				return nil, fmt.Errorf("property %q: %w", k, err)
			}
			cs.properties[k] = sub
		}
	}

	if req, ok := obj["required"].([]any); ok {
		for _, elem := range req {
			if s, ok := elem.(string); ok {
				cs.required = append(cs.required, s)
			}
		}
		sort.Strings(cs.required)
	}

	if ap, ok := obj["additionalProperties"]; ok {
		cs.hasAdditionalProps = true
		switch apv := ap.(type) {
		case bool:
			cs.allowAdditionalProps = apv
		case map[string]any:
			sub, err := compileSchemaObject(apv)
			if err != nil {
				return nil, fmt.Errorf("additionalProperties: %w", err)
			}
			cs.additionalPropSchema = sub
		}
	}

	if ev, ok := obj["enum"].([]any); ok {
		for _, item := range ev {
			b, err := canonicalValue(item)
			if err != nil {
				return nil, fmt.Errorf("enum value: %w", err)
			}
			cs.enumVals = append(cs.enumVals, b)
		}
	}

	if cv, ok := obj["const"]; ok {
		b, err := canonicalValue(cv)
		if err != nil {
			return nil, fmt.Errorf("const value: %w", err)
		}
		cs.hasConst = true
		cs.constVal = b
	}

	if v, ok := asInt(obj["minLength"]); ok {
		cs.minLength = &v
	}
	if v, ok := asInt(obj["maxLength"]); ok {
		cs.maxLength = &v
	}
	if pat, ok := obj["pattern"].(string); ok {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid schema regex %q: %w", pat, err)
		}
		cs.pattern = re
	}

	if v, ok := asFloat(obj["minimum"]); ok {
		cs.minimum = &v
	}
	if v, ok := asFloat(obj["maximum"]); ok {
		cs.maximum = &v
	}
	if v, ok := asFloat(obj["exclusiveMinimum"]); ok {
		cs.exclusiveMin = &v
	}
	if v, ok := asFloat(obj["exclusiveMaximum"]); ok {
		cs.exclusiveMax = &v
	}
	if v, ok := asFloat(obj["multipleOf"]); ok && v > 0 {
		cs.multipleOf = &v
	}

	if items, ok := obj["items"]; ok {
		if _, isArr := items.([]any); !isArr {
			sub, err := compileSchemaNode(items)
			if err != nil {
				return nil, fmt.Errorf("items: %w", err)
			}
			cs.items = sub
		}
	}
	if v, ok := asInt(obj["minItems"]); ok {
		cs.minItems = &v
	}
	if v, ok := asInt(obj["maxItems"]); ok {
		cs.maxItems = &v
	}
	if u, ok := obj["uniqueItems"].(bool); ok {
		cs.uniqueItems = u
	}

	var err error
	if cs.anyOf, err = compileSchemaList(obj["anyOf"]); err != nil {
		return nil, fmt.Errorf("anyOf: %w", err)
	}
	if cs.oneOf, err = compileSchemaList(obj["oneOf"]); err != nil {
		return nil, fmt.Errorf("oneOf: %w", err)
	}
	if cs.allOf, err = compileSchemaList(obj["allOf"]); err != nil {
		return nil, fmt.Errorf("allOf: %w", err)
	}

	return cs, nil
}

func compileSchemaList(raw any) ([]*CompiledSchema, error) {
	arr, ok := raw.([]any)
	if !ok {
		return nil, nil
	}
	out := make([]*CompiledSchema, 0, len(arr))
	for i, item := range arr {
		sub, err := compileSchemaNode(item)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out = append(out, sub)
	}
	return out, nil
}

// ValidateArguments validates a raw JSON params.arguments payload against the compiled schema.
// If argsRaw is empty or omitted, it is treated as an empty object {} for object schemas.
func (s *CompiledSchema) ValidateArguments(argsRaw json.RawMessage) error {
	if s == nil {
		return nil
	}
	trimmed := bytes.TrimSpace(argsRaw)
	if len(trimmed) == 0 {
		trimmed = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return fmt.Errorf("$.arguments: invalid json: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("$.arguments: unexpected trailing json token")
	}
	return s.validateValue("$.arguments", val)
}

func (s *CompiledSchema) validateValue(path string, val any) error {
	if len(s.types) > 0 {
		matched := false
		for _, expected := range s.types {
			if matchesJSONType(val, expected) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: expected type %s, got %s", path, strings.Join(s.types, "|"), actualJSONType(val))
		}
	}

	if s.hasConst {
		b, err := canonicalValue(val)
		if err != nil || !bytes.Equal(b, s.constVal) {
			return fmt.Errorf("%s: value does not match const constraint", path)
		}
	}

	if len(s.enumVals) > 0 {
		b, err := canonicalValue(val)
		if err != nil {
			return fmt.Errorf("%s: cannot canonicalize value for enum check", path)
		}
		found := false
		for _, allowed := range s.enumVals {
			if bytes.Equal(b, allowed) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: value not in allowed enum set", path)
		}
	}

	switch x := val.(type) {
	case string:
		runeLen := utf8.RuneCountInString(x)
		if s.minLength != nil && runeLen < *s.minLength {
			return fmt.Errorf("%s: string length %d < minLength %d", path, runeLen, *s.minLength)
		}
		if s.maxLength != nil && runeLen > *s.maxLength {
			return fmt.Errorf("%s: string length %d > maxLength %d", path, runeLen, *s.maxLength)
		}
		if s.pattern != nil && !s.pattern.MatchString(x) {
			return fmt.Errorf("%s: string does not match required pattern %q", path, s.pattern.String())
		}

	case json.Number:
		f, err := strconv.ParseFloat(x.String(), 64)
		if err != nil {
			return fmt.Errorf("%s: invalid number %q", path, x.String())
		}
		if s.minimum != nil && f < *s.minimum {
			return fmt.Errorf("%s: value %v < minimum %v", path, f, *s.minimum)
		}
		if s.maximum != nil && f > *s.maximum {
			return fmt.Errorf("%s: value %v > maximum %v", path, f, *s.maximum)
		}
		if s.exclusiveMin != nil && f <= *s.exclusiveMin {
			return fmt.Errorf("%s: value %v <= exclusiveMinimum %v", path, f, *s.exclusiveMin)
		}
		if s.exclusiveMax != nil && f >= *s.exclusiveMax {
			return fmt.Errorf("%s: value %v >= exclusiveMaximum %v", path, f, *s.exclusiveMax)
		}
		if s.multipleOf != nil {
			q := f / *s.multipleOf
			if math.Abs(q-math.Round(q)) > 1e-9 {
				return fmt.Errorf("%s: value %v is not a multiple of %v", path, f, *s.multipleOf)
			}
		}

	case []any:
		if s.minItems != nil && len(x) < *s.minItems {
			return fmt.Errorf("%s: array length %d < minItems %d", path, len(x), *s.minItems)
		}
		if s.maxItems != nil && len(x) > *s.maxItems {
			return fmt.Errorf("%s: array length %d > maxItems %d", path, len(x), *s.maxItems)
		}
		if s.items != nil {
			for i, elem := range x {
				if err := s.items.validateValue(fmt.Sprintf("%s[%d]", path, i), elem); err != nil {
					return err
				}
			}
		}
		if s.uniqueItems {
			seen := make(map[string]struct{}, len(x))
			for i, elem := range x {
				b, err := canonicalValue(elem)
				if err != nil {
					return fmt.Errorf("%s[%d]: canonicalize for uniqueItems: %w", path, i, err)
				}
				k := string(b)
				if _, dup := seen[k]; dup {
					return fmt.Errorf("%s[%d]: duplicate array element violates uniqueItems", path, i)
				}
				seen[k] = struct{}{}
			}
		}

	case map[string]any:
		for _, reqKey := range s.required {
			if _, ok := x[reqKey]; !ok {
				return fmt.Errorf("%s: missing required property %q", path, reqKey)
			}
		}
		// Sort keys for deterministic error reporting.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := x[k]
			childPath := path + "." + k
			if propSchema, ok := s.properties[k]; ok {
				if err := propSchema.validateValue(childPath, v); err != nil {
					return err
				}
				continue
			}
			if s.hasAdditionalProps {
				if !s.allowAdditionalProps {
					return fmt.Errorf("%s: additional property %q not allowed by pinned inputSchema", childPath, k)
				}
				if s.additionalPropSchema != nil {
					if err := s.additionalPropSchema.validateValue(childPath, v); err != nil {
						return err
					}
				}
			}
		}
	}

	if len(s.allOf) > 0 {
		for _, sub := range s.allOf {
			if err := sub.validateValue(path, val); err != nil {
				return err
			}
		}
	}
	if len(s.anyOf) > 0 {
		matched := false
		for _, sub := range s.anyOf {
			if sub.validateValue(path, val) == nil {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: value failed all anyOf subschemas", path)
		}
	}
	if len(s.oneOf) > 0 {
		matches := 0
		for _, sub := range s.oneOf {
			if sub.validateValue(path, val) == nil {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("%s: value matched %d oneOf subschemas (expected exactly 1)", path, matches)
		}
	}

	return nil
}

func matchesJSONType(val any, expected string) bool {
	switch expected {
	case "null":
		return val == nil
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "string":
		_, ok := val.(string)
		return ok
	case "array":
		_, ok := val.([]any)
		return ok
	case "object":
		_, ok := val.(map[string]any)
		return ok
	case "number":
		_, ok := val.(json.Number)
		return ok
	case "integer":
		num, ok := val.(json.Number)
		if !ok {
			return false
		}
		f, err := strconv.ParseFloat(num.String(), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return false
		}
		return math.Trunc(f) == f
	default:
		return false
	}
}

func actualJSONType(val any) string {
	switch val.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case json.Number:
		return "number"
	default:
		return fmt.Sprintf("%T", val)
	}
}

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(x.String(), 64)
		return f, err == nil
	case float64:
		return x, true
	case int:
		return float64(x), true
	default:
		return 0, false
	}
}

func asInt(v any) (int, bool) {
	f, ok := asFloat(v)
	if !ok || math.Trunc(f) != f {
		return 0, false
	}
	return int(f), true
}

func canonicalValue(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canon.JCS(raw)
}
