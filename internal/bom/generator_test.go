package bom

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverRepoMCPConfigsPromptsAndSignedA2ACard(t *testing.T) {
	dir := t.TempDir()

	// 1. .cursor/mcp.json with hardcoded Authorization header anti-pattern
	_ = os.MkdirAll(filepath.Join(dir, ".cursor"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".cursor", "mcp.json"), []byte(`{
		"mcpServers": {
			"jira-http": {
				"url": "https://jira-mcp.internal/mcp",
				"headers": { "Authorization": "Bearer hardcoded-leak" }
			}
		}
	}`), 0644)

	// 2. .vscode/mcp.json + claude_desktop_config.json
	_ = os.MkdirAll(filepath.Join(dir, ".vscode"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".vscode", "mcp.json"), []byte(`{
		"servers": {
			"local-fs": { "command": "npx", "args": ["-y", "@mcp/fs"] }
		}
	}`), 0644)
	_ = os.WriteFile(filepath.Join(dir, "claude_desktop_config.json"), []byte(`{
		"mcpServers": {
			"weather": { "command": "./mock-rugpull-mcp", "args": ["--mode=clean"] }
		}
	}`), 0644)

	// 3. System prompt with exact trailing newline (must NOT be trimmed)
	_ = os.MkdirAll(filepath.Join(dir, "prompts"), 0755)
	promptBytes := []byte("You are a SecOps triage agent.\nNever exfiltrate secrets.\n")
	_ = os.WriteFile(filepath.Join(dir, "prompts", "system.md"), promptBytes, 0644)
	wantPromptSum := sha256.Sum256(promptBytes)

	// 4. Signed A2A Agent Card (Ed25519)
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rawCard := []byte(`{
		"name": "triage-peer-agent",
		"version": "1.2.0",
		"url": "https://triage-peer.corp.internal",
		"description": "Peer security triage agent",
		"skills": [{"id": "lookup_cve", "name": "Lookup CVE", "description": "Fetches CVE details"}]
	}`)
	signedCard, err := SignA2ACardEd25519(rawCard, priv, "a2a-ed25519-1")
	if err != nil {
		t.Fatalf("SignA2ACardEd25519: %v", err)
	}
	_ = os.MkdirAll(filepath.Join(dir, ".well-known"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".well-known", "agent.json"), signedCard, 0644)

	// 5. RAG / Memory Data Stores manifest
	_ = os.WriteFile(filepath.Join(dir, "agbom-stores.json"), []byte(`{
		"stores": [
			{
				"name": "ir-playbook-vector-store",
				"store_type": "rag-knowledge",
				"access_mode": "read-only",
				"data_classification": "internal-confidential"
			}
		]
	}`), 0644)

	// 6. Lockfiles (go.mod, package-lock.json, requirements.txt, uv.lock)
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/agent\n\ngo 1.22\n\nrequire (\n\tgithub.com/example/sdk v1.2.3\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"packages":{"":{"name":"root"},"node_modules/@modelcontextprotocol/sdk":{"version":"1.5.0"}}}`), 0644)
	_ = os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("mcp==1.3.0\nhttpx>=0.27.0\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "uv.lock"), []byte("[[package]]\nname = \"pydantic\"\nversion = \"2.9.2\"\n"), 0644)

	report, err := DiscoverRepo(DiscoverOptions{
		RepoRoot:         dir,
		A2APublicKey:     pub,
		RequireSignedA2A: true,
	})
	if err != nil {
		t.Fatalf("DiscoverRepo: %v", err)
	}

	if len(report.MCPTargets) != 3 {
		t.Fatalf("expected 3 MCP targets across cursor/vscode/claude configs, got %d", len(report.MCPTargets))
	}

	foundAuthFinding := false
	for _, f := range report.Findings {
		if f.Code == "HARDCODED_AUTH_HEADER" && f.ToolName == "jira-http" {
			foundAuthFinding = true
		}
	}
	if !foundAuthFinding {
		t.Fatalf("expected HARDCODED_AUTH_HEADER finding, got %+v", report.Findings)
	}

	var foundA2A, foundPrompt, foundStore bool
	purls := map[string]bool{}
	for _, c := range report.Components {
		if proto, _ := c.GetProperty(PropProtocol); proto == "a2a/1.0" && c.Name == "triage-peer-agent" {
			status, _ := c.GetProperty(PropA2AJWSStatus)
			cardHash, _ := c.GetProperty(PropA2ACardSHA256)
			if status != "verified" || len(cardHash) != 64 {
				t.Fatalf("expected verified A2A card with sha256, got status=%q hash=%q", status, cardHash)
			}
			foundA2A = true
		}
		if ph, ok := c.GetProperty(PropSystemPromptSHA256); ok {
			if ph != hex.EncodeToString(wantPromptSum[:]) {
				t.Fatalf("expected exact raw-byte prompt sha256 %s, got %s", hex.EncodeToString(wantPromptSum[:]), ph)
			}
			foundPrompt = true
		}
		if c.Type == "data" && c.Name == "ir-playbook-vector-store" {
			mode, _ := c.GetProperty(PropAccessMode)
			if mode != "read-only" {
				t.Fatalf("expected data store access_mode read-only, got %q", mode)
			}
			foundStore = true
		}
		if c.Type == "library" && c.PURL != "" {
			purls[c.PURL] = true
		}
	}
	if !foundA2A || !foundPrompt || !foundStore {
		t.Fatalf("missing discovered components: foundA2A=%v foundPrompt=%v foundStore=%v", foundA2A, foundPrompt, foundStore)
	}
	for _, wantPURL := range []string{
		"pkg:golang/github.com/example/sdk@v1.2.3",
		"pkg:npm/@modelcontextprotocol/sdk@1.5.0",
		"pkg:pypi/mcp@1.3.0",
		"pkg:pypi/pydantic@2.9.2",
	} {
		if !purls[wantPURL] {
			t.Fatalf("expected lockfile PURL %q in discovered libraries, got %+v", wantPURL, purls)
		}
	}
}

func TestA2ACardES256PEMAndJWKAndTamperFailsClosed(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}

	pkixDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})
	loadedPEM, err := LoadJWSVerifyKey(pemBytes)
	if err != nil {
		t.Fatalf("LoadJWSVerifyKey PEM: %v", err)
	}

	xBuf := make([]byte, 32)
	yBuf := make([]byte, 32)
	priv.PublicKey.X.FillBytes(xBuf)
	priv.PublicKey.Y.FillBytes(yBuf)
	jwkBytes, _ := json.Marshal(map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBuf),
		"y":   base64.RawURLEncoding.EncodeToString(yBuf),
	})
	loadedJWK, err := LoadJWSVerifyKey(jwkBytes)
	if err != nil {
		t.Fatalf("LoadJWSVerifyKey JWK: %v", err)
	}

	rawCard := []byte(`{"name":"finance-peer","version":"2.0.0","url":"https://finance.corp.internal"}`)
	signed, err := SignA2ACardES256(rawCard, priv, "es256-1")
	if err != nil {
		t.Fatalf("SignA2ACardES256: %v", err)
	}

	for name, pub := range map[string]any{"PEM": loadedPEM, "JWK": loadedJWK} {
		_, status, err := VerifyA2ACardJWS(signed, pub)
		if err != nil || status != "verified" {
			t.Fatalf("%s verification failed: status=%s err=%v", name, status, err)
		}
	}

	tampered := []byte(strings.ReplaceAll(string(signed), "finance-peer", "evil-peer"))
	_, status, err := VerifyA2ACardJWS(tampered, loadedPEM)
	if err == nil || status != "invalid" {
		t.Fatalf("expected tampered A2A card to fail verification, got status=%s err=%v", status, err)
	}

	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".well-known"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".well-known", "agent.json"), rawCard, 0644)
	if _, err := DiscoverRepo(DiscoverOptions{
		RepoRoot:         dir,
		A2APublicKey:     loadedPEM,
		RequireSignedA2A: true,
	}); err == nil {
		t.Fatal("expected unsigned A2A card to fail when RequireSignedA2A=true")
	}
}

func TestSymlinkEscapeAndMalformedPackageLockRejected(t *testing.T) {
	// 1. Symlink inside prompts/ pointing outside RepoRoot must fail closed.
	outsideDir := t.TempDir()
	secretFile := filepath.Join(outsideDir, "outside_secret.txt")
	_ = os.WriteFile(secretFile, []byte("TOP_SECRET"), 0600)

	repoDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(repoDir, "prompts"), 0755)
	if err := os.Symlink(secretFile, filepath.Join(repoDir, "prompts", "leak.md")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := DiscoverRepo(DiscoverOptions{RepoRoot: repoDir}); err == nil {
		t.Fatal("expected symlink escaping RepoRoot to be rejected")
	}

	// 2. Malformed package-lock.json must return an error instead of silently returning empty.
	repoDir2 := t.TempDir()
	_ = os.WriteFile(filepath.Join(repoDir2, "package-lock.json"), []byte("{not-valid-json"), 0644)
	if _, err := DiscoverRepo(DiscoverOptions{RepoRoot: repoDir2}); err == nil {
		t.Fatal("expected malformed package-lock.json to return error")
	}
}
