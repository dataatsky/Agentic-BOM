---
trigger: model_decision
description: Load when editing RFC 8785 JCS canonicalization, two-level SHA-256 hashing, pagination aggregation, or static MCP tool linting in internal/canon.
---

# MCP Canonicalization & Static Linting Rules

## Rule A: Separate Volatile Envelope from Semantic Surface
- Strip JSON-RPC transport fields (`id`, `nextCursor`, caching hints such as `ttlMs`, `cacheScope`, `resultType`).
- Pin every field inside each tool object verbatim, including `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `execution`, `icons`, `_meta`, and any undocumented keys.

## Rule B: Pagination & Duplicate Rejection
- Follow `nextCursor` up to `50` pages; fail closed if pagination exceeds the cap.
- Reject duplicate `tool.name` values across pages immediately to prevent tool shadowing ambiguity.
- Sort per-tool pins deterministically by exact raw UTF-8 byte order of `tool.name`.

## Rule C: RFC 8785 (JCS) & Two-Level Digests
- Recursively sort JSON object keys by **UTF-16 code units** (RFC 8785 §3.2.3).
- Emit zero insignificant whitespace outside strings.
- Format numbers per ECMAScript / RFC 8785 §3.2.2.3 (`-0` -> `0`, `1.0` -> `1`).
- Do **not** HTML-escape `<`, `>`, or `&`.
- Compute:
  1. `tool_sha256 = SHA256(JCS(raw_tool_json))`
  2. `tools_list_sha256 = SHA256(join("\n", "<name>:<tool_sha256>" for each sorted tool))`

## Rule D: Companion Static Linter (`internal/canon/linter.go`)
- Flag `CRITICAL`:
  - Invisible Unicode Tags (`U+E0000–U+E007F`)
  - Zero-width characters (`U+200B–U+200D`, `U+FEFF`)
  - Trojan Source bidi overrides (`U+202A–U+202E`, `U+2066–U+2069`)
- Flag `HIGH`:
  - `x-mcp-header` annotations mirroring LLM arguments into HTTP headers
  - Excessive consecutive newlines (`>= 5`) and prompt-injection/shadowing phrases
  - Destructive tool prefixes (`delete_`, `remove_`, `drop_`, `exec_`, `write_`, `run_`, `destroy_`) claiming `annotations.readOnlyHint: true`
- Flag `MEDIUM`:
  - Descriptions exceeding 1,500 runes
  - Destructive object schemas missing `"additionalProperties": false`
