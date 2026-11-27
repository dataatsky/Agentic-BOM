package mcpclient

import (
	"errors"
	"strings"
	"unicode"
)

// SplitCommandArgs splits a command-line argument string respecting single quotes ('...'),
// double quotes ("..."), and backslash escapes outside single quotes.
// It returns an error if any quote or trailing escape is left unterminated.
func SplitCommandArgs(input string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inToken := false
	var quote rune // 0, '\'', or '"'
	escaped := false

	for _, r := range input {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			inToken = true
			continue
		}
		if quote == '\'' {
			if r == '\'' {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			continue
		}
		if quote == '"' {
			switch r {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			default:
				cur.WriteRune(r)
			}
			continue
		}

		switch {
		case r == '\\':
			escaped = true
			inToken = true
		case r == '\'' || r == '"':
			quote = r
			inToken = true
		case unicode.IsSpace(r):
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}

	if escaped {
		return nil, errors.New("unterminated backslash escape in command arguments")
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote in command arguments")
	}
	if inToken {
		args = append(args, cur.String())
	}
	return args, nil
}
