---
name: verify-agbom-gate
description: >-
  Runs the full unit and adversarial E2E test suite for agbom-gate, builds both
  binaries, and executes a live startup rug-pull quarantine demonstration.
---

# Verify agbom-gate

Follow these steps to verify all security controls in `agbom-gate`:

1. **Run Unit & Adversarial E2E Tests:**
   ```bash
   go test -race -v ./...
   ```
   Confirm all tests pass with zero data races.

2. **Build Binaries:**
   ```bash
   go build -o bin/agbom-gate ./cmd/agbom-gate
   go build -o bin/mock-rugpull-mcp ./testdata/mock-rugpull-mcp
   ```

3. **Run Live Rug-Pull Quarantine Demo:**
   Execute the end-to-end CLI flow in `/tmp/agbom-demo`:
   - Generate Ed25519 signing keys:
     ```bash
     rm -rf /tmp/agbom-demo && mkdir -p /tmp/agbom-demo
     ./bin/agbom-gate keygen --out /tmp/agbom-demo
     ```
   - Scan the mock server in clean mode to produce a signed `agbom.json` + `agbom.dsse.sig`:
     ```bash
     ./bin/agbom-gate scan \
       --server-name weather-mcp \
       --cmd ./bin/mock-rugpull-mcp \
       --args "--mode=clean" \
       --allowed-tools "get_forecast" \
       --sign-key /tmp/agbom-demo/agbom.key \
       --out /tmp/agbom-demo/agbom.json \
       --sig-out /tmp/agbom-demo/agbom.dsse.sig
     ```
   - Launch the quarantine proxy against `--mode=rugpull-immediate` and send an `initialize` + `tools/list` JSON-RPC pair over stdin:
     ```bash
     printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' | \
       ./bin/agbom-gate proxy \
         --agbom /tmp/agbom-demo/agbom.json \
         --sig /tmp/agbom-demo/agbom.dsse.sig \
         --pub-key /tmp/agbom-demo/agbom.pub \
         --server-name weather-mcp \
         --cmd ./bin/mock-rugpull-mcp \
         --args "--mode=rugpull-immediate" \
         --telemetry-log /tmp/agbom-demo/dfir.ndjson
     ```
   - Verify:
     - JSON-RPC response returns error code `-32099` (`MCP_SERVER_QUARANTINED_HASH_MISMATCH`).
     - `/tmp/agbom-demo/dfir.ndjson` contains an `agbom/quarantined` JSON record with `expected_hash`, `observed_hash`, and `"drifted_tools":["get_forecast"]`.

4. **Report Results:**
   Summarize test counts, binary sizes, and the captured `agbom/quarantined` telemetry JSON.
