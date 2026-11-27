---
name: extend-agbom-gate
description: >-
  Guides parallel or phased implementation of Phase 2 features for agbom-gate
  including Streamable HTTP MCP transport, JSON Schema runtime argument
  validation, repo config discovery, and OpenTelemetry OTLP export.
---

# Extend agbom-gate (Phase 2 Roadmap)

Use this skill when upgrading `agbom-gate` from the zero-dependency Phase 1 MVP to full enterprise readiness. Preserve all invariants in `.agents/rules/security-invariants.md`.

## Recommended Implementation Phases

1. **Repo Discovery (`internal/bom/generator.go`):**
   - Scan `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, and `/.well-known/agent.json` (A2A Agent Cards).
   - Add JWS signature verification checks for discovered A2A Agent Cards.
   - Hash local system prompt files (`agbom:system_prompt_sha256`).

2. **Streamable HTTP Transport (`internal/mcpclient/transport_http.go` & `internal/proxy/http_proxy.go`):**
   - Support MCP Streamable HTTP + SSE notifications.
   - Enforce mTLS or external OBO token brokering; explicitly reject token passthrough.

3. **Runtime Argument Validation (`internal/proxy/validator.go`):**
   - Cache each pinned tool's `inputSchema` during `VERIFYING`.
   - Validate every `tools/call` `params.arguments` payload against the pinned schema before forwarding upstream, rejecting undeclared fields when `additionalProperties: false`.

4. **OpenTelemetry Span Export (`internal/telemetry/otel.go`):**
   - Map `agbom/snapshot`, `agbom/quarantined`, and `agbom/tool_blocked` to OTLP spans carrying `agbom.server.name`, `agbom.tools_list.sha256`, `agbom.drift.tools`, and `agbom.nhi.principal` so DFIR replay pipelines can correlate tool drift with downstream API calls.

After each phase, invoke `/verify-agbom-gate` to confirm zero regressions.
