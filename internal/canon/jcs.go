package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// JCS transforms a valid JSON document into its RFC 8785 JSON Canonicalization Scheme byte sequence.
// It preserves all object keys (including unmodeled/_meta fields) and exact string contents verbatim.
func JCS(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	// Reject trailing garbage after the root JSON value.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("unexpected trailing json token")
		}
		return nil, fmt.Errorf("invalid trailing json: %w", err)
	}

	var buf bytes.Buffer
	if err := writeJCSValue(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeJCSValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		return writeJCSNumber(buf, x)
	case string:
		writeJCSString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCSValue(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// RFC 8785 Section 3.2.3: sort property names by UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool {
			return lessUTF16(keys[i], keys[j])
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, k)
			buf.WriteByte(':')
			if err := writeJCSValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported json value type %T", v)
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeJCSNumber(buf *bytes.Buffer, num json.Number) error {
	f, err := strconv.ParseFloat(num.String(), 64)
	if err != nil {
		return fmt.Errorf("invalid json number %q: %w", num.String(), err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("non-finite json number %q", num.String())
	}
	if f == 0 {
		buf.WriteByte('0')
		return nil
	}
	// Format per ECMAScript / RFC 8785 Section 3.2.2.3 rules.
	abs := math.Abs(f)
	var s string
	if abs >= 1e-6 && abs < 1e21 {
		s = strconv.FormatFloat(f, 'f', -1, 64)
	} else {
		s = strconv.FormatFloat(f, 'e', -1, 64)
		// Remove leading zeros from exponent (e.g., e+07 -> e+7).
		if idx := strings.IndexByte(s, 'e'); idx != -1 {
			mantissa := s[:idx]
			sign := s[idx+1 : idx+2]
			expStr := strings.TrimLeft(s[idx+2:], "0")
			if expStr == "" {
				expStr = "0"
			}
			s = mantissa + "e" + sign + expStr
		}
	}
	buf.WriteString(s)
	return nil
}

// writeJCSString serializes a JSON string per RFC 8785 Section 3.2.2.2
// without Go's default HTML-escaping of '<', '>', and '&'.
func writeJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r >= 0 && r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
