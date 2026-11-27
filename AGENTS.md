# agbom-gate — Agent Bill of Materials (AgBOM) & MCP Quarantine Proxy

`agbom-gate` is a zero-dependency Go 1.22+ CLI and fail-closed MCP security proxy implementing signed **CycloneDX 1.6 Agent Bills of Materials (AgBOM)** aligned with the **OWASP Agent Observability Standard (AOS)** and **Agent Control Standard (ACS)**.

## Architecture Overview

- **Control Plane (Build / CI):**
  - `agbom-gate keygen` — generates Ed25519 keypairs (`agbom.key`, `agbom.pub`) for DSSE signing.
  - `agbom-gate scan` — queries stdio or Streamable HTTP MCP servers (`initialize` + paginated `tools/list`), discovers local repo configs (`.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`), lockfiles (`go.mod`, `package-lock.json`, `requirements.txt`, `uv.lock`), RAG/memory data stores (`agbom-stores.json`, `.agents/stores.json`), verifies A2A Agent Card JWS signatures (`EdDSA` / `ES256`), hashes raw system prompts (`agbom:system_prompt_sha256`), optionally probes discovered MCP servers (`--probe-discovered`), runs static injection/Unicode/header/cross-tool-shadowing linting, computes two-level RFC 8785 JCS SHA-256 digests, emits CycloneDX 1.6 `agbom.json`, and signs an Ed25519 DSSE envelope (`agbom.dsse.sig`).
  - `agbom-gate diff` — compares base vs. PR head AgBOMs, outputs a GitHub Markdown authority diff, and exits `2` on security-relevant drift (`TOOLS_HASH_DRIFT`, `WRITE_CAPABILITY_ESCALATION`, `AUTHORITY_EXPANSION`, `HITL_GATE_REMOVED`, `NEW_MCP_SERVER`, `NEW_A2A_AGENT`, `TOKEN_PASSTHROUGH_ENABLED`, `SYSTEM_PROMPT_DRIFT`, `A2A_CARD_DRIFT`, `A2A_SIGNATURE_DOWNGRADE`, `DATA_ACCESS_ESCALATION`, `NEW_DATA_STORE`).
  - `agbom-gate reconcile` — reconciles a signed AgBOM against live ACS NDJSON or OTLP/HTTP JSON traces to detect `SHADOW_MCP_SERVER`, `SHADOW_DATA_STORE`, `UNDECLARED_TOOL_CALL`, `RUNTIME_HASH_DRIFT`, and `QUARANTINE_EVENT_OBSERVED` (exits `2`).
- **Data Plane (Runtime):**
  - `agbom-gate proxy` — verifies the signed AgBOM Ed25519 DSSE envelope before boot (fail-closed), runs in stdio, single-server Streamable HTTP + SSE, or multi-server `--routes` `HTTPGateway` mode (`/mcp/{server-name}` with mTLS / brokered OBO and raw client `Authorization` stripping), intercepts `tools/list` and `notifications/tools/list_changed`, enforces `agbom:allowed_tools`, `agbom:step_up_approval_tools` (`-32097`, with optional `--approval-webhook`), and pinned `inputSchema` JSON Schema argument validation (`-32096`), quarantines drifted servers with JSON-RPC `-32099`, and emits dual-sink OWASP ACS NDJSON (with redacted drift snippets) + OTLP/HTTP traces (`agbom/snapshot`, `agbom/quarantined`, `agbom/tool_blocked`, `agbom/step_up_approved`).

## Repository Layout

- `cmd/agbom-gate/main.go` — CLI entrypoint (`keygen`, `scan`, `diff`, `reconcile`, `proxy`)
- `internal/canon/` — Pure Go RFC 8785 JCS canonicalizer, two-level SHA-256 hasher (with annotation pin metadata), and static injection/Unicode/cross-tool-shadowing linter
- `internal/bom/` — CycloneDX 1.6 `agbom:*` schema, Ed25519 DSSE signer/verifier, repo/lockfile/data-store/prompt discovery (`generator.go`), and A2A Agent Card JWS verifier (`jws.go`)
- `internal/diff/` — PR authority-diff engine and Markdown renderer
- `internal/reconcile/` — Runtime-to-declared reconciliation engine for ACS NDJSON & OTLP JSON telemetry
- `internal/mcpclient/` — Stdio & Streamable HTTP/SSE JSON-RPC 2.0 MCP clients with mTLS, brokered OBO, and pagination DoS guard
- `internal/proxy/` — Fail-closed stdio, Streamable HTTP/SSE, and multi-server `HTTPGateway` quarantine proxies, external HITL approval webhook & payload redactor (`approval.go`), and pinned JSON Schema argument validator (`validator.go`)
- `internal/telemetry/` — Structured OWASP ACS NDJSON DFIR logger + zero-dependency OTLP/HTTP JSON span exporter (`otel.go`)
- `testdata/mock-rugpull-mcp/` — Deterministic adversarial stdio + Streamable HTTP MCP server for tests and demos
- `testdata/vectors/` — Standalone golden canonicalization & attack payload fixtures
- `.github/workflows/agbom-diff.yml` — CI PR authority-diff workflow with sticky PR comment posting

## Common Commands

```bash
# Run all unit + adversarial E2E tests with the race detector
go test -race -v ./...

# Build binaries
go build -o bin/agbom-gate ./cmd/agbom-gate
go build -o bin/mock-rugpull-mcp ./testdata/mock-rugpull-mcp
```
