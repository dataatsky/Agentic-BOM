---
trigger: always_on
description: Core security invariants that must never be violated when modifying agbom-gate.
---

# Security Invariants for agbom-gate

1. **Zero-Dependency Stdlib Core:** Keep Phase 1 packages in pure Go standard library (`go.mod` has no external dependencies) so verification and builds run reliably offline.
2. **Hash Raw Tool JSON (No Struct Round-Tripping):** Never unmarshal a tool into a strict Go struct and re-marshal before hashing. Pass raw `json.RawMessage` directly into `canon.JCS` so undocumented or `_meta` smuggling fields always trigger hash drift.
3. **Preserve Exact String Bytes Before Hashing:** Never trim whitespace, collapse newlines, or strip Unicode characters from tool descriptions, titles, or schema strings prior to computing SHA-256 hashes.
4. **Fail-Closed Cryptographic Boot:** `agbom-gate proxy` must verify the Ed25519 DSSE signature (using DSSEv1 Pre-Authentication Encoding) and verify exact byte-for-byte payload equality against `agbom.json` before starting upstream servers.
5. **Mid-Session Rug-Pull Interception:** Never forward `notifications/tools/list_changed` directly from an upstream MCP server to the LLM client. Always re-fetch and re-verify `tools/list` first, and transition permanently to `QUARANTINED` (`-32099`) on any hash mismatch.
6. **Blast-Radius Isolation & Least Privilege:** Strip tools outside `agbom:allowed_tools` from `tools/list` responses and reject forged `tools/call` requests for unapproved or step-up-gated tools without forwarding upstream.
7. **No Token Passthrough:** Upstream MCP servers must never receive raw upstream client tokens via passthrough; enforce external brokered OBO (`agbom:token_passthrough = forbidden-brokered-obo`).
8. **Pagination DoS Guard:** Enforce a hard cap (`50` pages) on `tools/list` `nextCursor` pagination and reject duplicate tool names across pages.
