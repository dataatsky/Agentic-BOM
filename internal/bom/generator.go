package bom

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/secops/agbom-gate/internal/canon"
)

// DiscoverOptions controls repository configuration, lockfile, data-store, A2A card, and system prompt discovery.
type DiscoverOptions struct {
	RepoRoot         string
	PromptFiles      []string
	A2APublicKey     crypto.PublicKey
	RequireSignedA2A bool
}

// DiscoveredMCPTarget describes an MCP server entry discovered from IDE/agent config files.
type DiscoveredMCPTarget struct {
	Name       string
	SourceFile string
	Transport  string // "stdio" or "streamable-http"
	Command    string
	Args       []string
	URL        string
}

// DiscoveryReport aggregates components, MCP targets, and static findings discovered in a repo.
type DiscoveryReport struct {
	Components []Component
	MCPTargets []DiscoveredMCPTarget
	Findings   []canon.Finding
}

// DiscoverRepo scans a target repository for MCP client configs (.cursor/mcp.json,
// .vscode/mcp.json, claude_desktop_config.json), A2A Agent Cards (/.well-known/agent.json),
// RAG/memory data-store manifests (agbom-stores.json, .agents/stores.json),
// package lockfiles (go.mod, package-lock.json, requirements.txt, uv.lock),
// and system prompt files, returning CycloneDX 1.6 components and static security findings.
// All discovered files are verified via EvalSymlinks to reside strictly inside RepoRoot.
func DiscoverRepo(opts DiscoverOptions) (*DiscoveryReport, error) {
	if opts.RepoRoot == "" {
		return nil, fmt.Errorf("repo root is required")
	}
	absRoot, err := filepath.Abs(opts.RepoRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repo root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("eval repo root symlinks: %w", err)
	}

	report := &DiscoveryReport{}

	// 1. Discover MCP client configs
	mcpConfigPaths := []string{
		filepath.Join(".cursor", "mcp.json"),
		filepath.Join(".vscode", "mcp.json"),
		"claude_desktop_config.json",
		filepath.Join(".claude", "claude_desktop_config.json"),
	}
	for _, rel := range mcpConfigPaths {
		raw, exists, err := readContainedOptionalFile(realRoot, filepath.Join(absRoot, rel))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rel, err)
		}
		if !exists {
			continue
		}
		if err := parseMCPConfig(rel, raw, report); err != nil {
			return nil, fmt.Errorf("parse %s: %w", rel, err)
		}
	}

	// 2. Discover A2A Agent Cards
	a2aCardPaths := []string{
		filepath.Join(".well-known", "agent.json"),
		"agent.json",
	}
	for _, rel := range a2aCardPaths {
		raw, exists, err := readContainedOptionalFile(realRoot, filepath.Join(absRoot, rel))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rel, err)
		}
		if !exists {
			continue
		}
		if err := parseA2ACard(rel, raw, opts, report); err != nil {
			return nil, err
		}
	}

	// 3. Discover RAG / memory data-store manifests
	storePaths := []string{
		"agbom-stores.json",
		filepath.Join(".agents", "stores.json"),
	}
	for _, rel := range storePaths {
		raw, exists, err := readContainedOptionalFile(realRoot, filepath.Join(absRoot, rel))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rel, err)
		}
		if !exists {
			continue
		}
		if err := parseDataStores(rel, raw, report); err != nil {
			return nil, fmt.Errorf("parse %s: %w", rel, err)
		}
	}

	// 4. Discover package lockfiles into CycloneDX library components
	if err := discoverLockfiles(absRoot, realRoot, report); err != nil {
		return nil, err
	}

	// 5. Discover and hash system prompt files (exact raw bytes — never trimmed)
	promptRelPaths := collectPromptFiles(absRoot, opts.PromptFiles)
	for _, rel := range promptRelPaths {
		full := rel
		displayPath := rel
		if !filepath.IsAbs(rel) {
			full = filepath.Join(absRoot, rel)
		} else if r, err := filepath.Rel(absRoot, rel); err == nil {
			displayPath = r
		}
		raw, err := readContainedRequiredFile(realRoot, full)
		if err != nil {
			return nil, fmt.Errorf("read prompt file %s: %w", displayPath, err)
		}
		sum := sha256.Sum256(raw)
		report.Components = append(report.Components, Component{
			Type:    "machine-learning-model",
			Name:    "prompt:" + filepath.ToSlash(displayPath),
			Version: "pinned",
			Properties: []Property{
				{Name: PropSourceFile, Value: filepath.ToSlash(displayPath)},
				{Name: PropSystemPromptSHA256, Value: hex.EncodeToString(sum[:])},
			},
		})
	}

	return report, nil
}

// readContainedOptionalFile reads candidatePath only after verifying that its resolved
// real path (following symlinks) stays inside realRoot.
func readContainedOptionalFile(realRoot, candidatePath string) ([]byte, bool, error) {
	if _, err := os.Lstat(candidatePath); err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	b, err := readContainedRequiredFile(realRoot, candidatePath)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func readContainedRequiredFile(realRoot, candidatePath string) ([]byte, error) {
	realTarget, err := filepath.EvalSymlinks(candidatePath)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(realRoot, realTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("path %q escapes repository root %q", candidatePath, realRoot)
	}
	return os.ReadFile(realTarget)
}

func parseDataStores(relPath string, raw []byte, report *DiscoveryReport) error {
	var manifest struct {
		Stores []struct {
			Name               string `json:"name"`
			StoreType          string `json:"store_type"`
			AccessMode         string `json:"access_mode"`
			DataClassification string `json:"data_classification"`
		} `json:"stores"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	for _, s := range manifest.Stores {
		if strings.TrimSpace(s.Name) == "" {
			continue
		}
		props := []Property{
			{Name: PropSourceFile, Value: filepath.ToSlash(relPath)},
		}
		if s.StoreType != "" {
			props = append(props, Property{Name: PropStoreType, Value: s.StoreType})
		}
		if s.AccessMode != "" {
			props = append(props, Property{Name: PropAccessMode, Value: s.AccessMode})
		}
		if s.DataClassification != "" {
			props = append(props, Property{Name: PropDataClassification, Value: s.DataClassification})
		}
		report.Components = append(report.Components, Component{
			Type:       "data",
			Name:       s.Name,
			Properties: props,
		})
	}
	return nil
}

func discoverLockfiles(absRoot, realRoot string, report *DiscoveryReport) error {
	seenPURL := map[string]struct{}{}
	addLib := func(name, version, purl, src string) {
		if name == "" || purl == "" {
			return
		}
		if _, dup := seenPURL[purl]; dup {
			return
		}
		seenPURL[purl] = struct{}{}
		report.Components = append(report.Components, Component{
			Type:    "library",
			Name:    name,
			Version: version,
			PURL:    purl,
			Properties: []Property{
				{Name: PropSourceFile, Value: src},
			},
		})
	}

	// go.mod
	if raw, ok, err := readContainedOptionalFile(realRoot, filepath.Join(absRoot, "go.mod")); err != nil {
		return fmt.Errorf("read go.mod: %w", err)
	} else if ok {
		for _, lib := range parseGoMod(raw) {
			addLib(lib.name, lib.version, fmt.Sprintf("pkg:golang/%s@%s", lib.name, lib.version), "go.mod")
		}
	}

	// package-lock.json
	if raw, ok, err := readContainedOptionalFile(realRoot, filepath.Join(absRoot, "package-lock.json")); err != nil {
		return fmt.Errorf("read package-lock.json: %w", err)
	} else if ok {
		libs, err := parsePackageLock(raw)
		if err != nil {
			return fmt.Errorf("parse package-lock.json: %w", err)
		}
		for _, lib := range libs {
			addLib(lib.name, lib.version, fmt.Sprintf("pkg:npm/%s@%s", lib.name, lib.version), "package-lock.json")
		}
	}

	// requirements.txt
	if raw, ok, err := readContainedOptionalFile(realRoot, filepath.Join(absRoot, "requirements.txt")); err != nil {
		return fmt.Errorf("read requirements.txt: %w", err)
	} else if ok {
		for _, lib := range parseRequirementsTxt(raw) {
			purl := fmt.Sprintf("pkg:pypi/%s", lib.name)
			if lib.version != "" {
				purl += "@" + lib.version
			}
			addLib(lib.name, lib.version, purl, "requirements.txt")
		}
	}

	// uv.lock
	if raw, ok, err := readContainedOptionalFile(realRoot, filepath.Join(absRoot, "uv.lock")); err != nil {
		return fmt.Errorf("read uv.lock: %w", err)
	} else if ok {
		for _, lib := range parseUVLock(raw) {
			addLib(lib.name, lib.version, fmt.Sprintf("pkg:pypi/%s@%s", lib.name, lib.version), "uv.lock")
		}
	}

	return nil
}

type pkgEntry struct {
	name    string
	version string
}

func parseGoMod(raw []byte) []pkgEntry {
	var out []pkgEntry
	sc := bufio.NewScanner(bytes.NewReader(raw))
	inRequire := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if idx := strings.Index(line, "//"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			fields := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(fields) >= 2 {
				out = append(out, pkgEntry{name: fields[0], version: fields[1]})
			}
			continue
		}
		if inRequire {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				out = append(out, pkgEntry{name: fields[0], version: fields[1]})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func parsePackageLock(raw []byte) ([]pkgEntry, error) {
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	seen := map[string]string{}
	for path, info := range doc.Packages {
		if path == "" || info.Version == "" {
			continue
		}
		name := path
		if idx := strings.LastIndex(path, "node_modules/"); idx != -1 {
			name = path[idx+len("node_modules/"):]
		}
		seen[name] = info.Version
	}
	for name, info := range doc.Dependencies {
		if name != "" && info.Version != "" {
			if _, ok := seen[name]; !ok {
				seen[name] = info.Version
			}
		}
	}
	out := make([]pkgEntry, 0, len(seen))
	for k, v := range seen {
		out = append(out, pkgEntry{name: k, version: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func parseRequirementsTxt(raw []byte) []pkgEntry {
	var out []pkgEntry
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		name := line
		version := ""
		for _, sep := range []string{"==", ">=", "<=", "~=", "!="} {
			if idx := strings.Index(line, sep); idx != -1 {
				name = strings.TrimSpace(line[:idx])
				version = strings.TrimSpace(line[idx+len(sep):])
				if comma := strings.Index(version, ","); comma != -1 {
					version = strings.TrimSpace(version[:comma])
				}
				break
			}
		}
		if bracket := strings.Index(name, "["); bracket != -1 {
			name = strings.TrimSpace(name[:bracket])
		}
		if name != "" {
			out = append(out, pkgEntry{name: strings.ToLower(name), version: version})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func parseUVLock(raw []byte) []pkgEntry {
	var out []pkgEntry
	sc := bufio.NewScanner(bytes.NewReader(raw))
	inPkg := false
	var curName, curVer string
	flush := func() {
		if inPkg && curName != "" && curVer != "" {
			out = append(out, pkgEntry{name: curName, version: curVer})
		}
		curName = ""
		curVer = ""
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "[[package]]" {
			flush()
			inPkg = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			inPkg = false
			continue
		}
		if !inPkg {
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			curName = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		} else if strings.HasPrefix(line, "version = ") {
			curVer = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}
	flush()
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func parseMCPConfig(relPath string, raw []byte, report *DiscoveryReport) error {
	var cfg struct {
		MCPServers map[string]mcpServerEntry `json:"mcpServers"`
		Servers    map[string]mcpServerEntry `json:"servers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}

	merged := map[string]mcpServerEntry{}
	for k, v := range cfg.MCPServers {
		merged[k] = v
	}
	for k, v := range cfg.Servers {
		merged[k] = v
	}

	names := make([]string, 0, len(merged))
	for k := range merged {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		entry := merged[name]
		transport := "stdio"
		endpoint := ""
		if entry.URL != "" {
			transport = "streamable-http"
			endpoint = entry.URL
		}

		for hk := range entry.Headers {
			lower := strings.ToLower(hk)
			if lower == "authorization" || strings.Contains(lower, "token") || strings.Contains(lower, "api-key") {
				report.Findings = append(report.Findings, canon.Finding{
					Severity:  "HIGH",
					Code:      "HARDCODED_AUTH_HEADER",
					ToolName:  name,
					FieldPath: fmt.Sprintf("%s#/%s/headers/%s", filepath.ToSlash(relPath), name, hk),
					Message:   fmt.Sprintf("hardcoded credential header %q in %s violates brokered OBO isolation", hk, filepath.ToSlash(relPath)),
				})
			}
		}

		report.MCPTargets = append(report.MCPTargets, DiscoveredMCPTarget{
			Name:       name,
			SourceFile: filepath.ToSlash(relPath),
			Transport:  transport,
			Command:    entry.Command,
			Args:       entry.Args,
			URL:        entry.URL,
		})

		props := []Property{
			{Name: PropProtocol, Value: "mcp/2026-07"},
			{Name: PropTransport, Value: transport},
			{Name: PropTokenPassthru, Value: "forbidden-brokered-obo"},
			{Name: PropSourceFile, Value: filepath.ToSlash(relPath)},
		}
		if endpoint != "" {
			props = append(props, Property{Name: PropEndpoint, Value: endpoint})
		}
		report.Components = append(report.Components, Component{
			Type:       "service",
			Name:       name,
			Version:    "discovered",
			Properties: props,
		})
	}
	return nil
}

type mcpServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

func parseA2ACard(relPath string, raw []byte, opts DiscoverOptions, report *DiscoveryReport) error {
	canonicalBytes, status, verifyErr := VerifyA2ACardJWS(raw, opts.A2APublicKey)
	if len(canonicalBytes) == 0 {
		return fmt.Errorf("A2A agent card %s invalid: %w", relPath, verifyErr)
	}

	var cardMeta struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		URL     string `json:"url"`
	}
	_ = json.Unmarshal(canonicalBytes, &cardMeta)
	if cardMeta.Name == "" {
		cardMeta.Name = "a2a-agent"
	}
	if cardMeta.Version == "" {
		cardMeta.Version = "1.0.0"
	}

	lintFindings, err := canon.LintTool(canonicalBytes)
	if err == nil {
		for _, f := range lintFindings {
			if f.ToolName == "" {
				f.ToolName = cardMeta.Name
			}
			f.FieldPath = filepath.ToSlash(relPath) + ":" + f.FieldPath
			report.Findings = append(report.Findings, f)
		}
	}

	if status != "verified" {
		sev := "HIGH"
		code := "A2A_CARD_UNSIGNED"
		msg := fmt.Sprintf("A2A Agent Card %s is unsigned (spoofing risk)", filepath.ToSlash(relPath))
		if status == "invalid" {
			sev = "CRITICAL"
			code = "A2A_CARD_INVALID_JWS"
			msg = fmt.Sprintf("A2A Agent Card %s failed JWS verification: %v", filepath.ToSlash(relPath), verifyErr)
		}
		report.Findings = append(report.Findings, canon.Finding{
			Severity:  sev,
			Code:      code,
			ToolName:  cardMeta.Name,
			FieldPath: filepath.ToSlash(relPath),
			Message:   msg,
		})
		if opts.RequireSignedA2A {
			return fmt.Errorf("%s: %s", code, msg)
		}
	}

	sum := sha256.Sum256(canonicalBytes)
	props := []Property{
		{Name: PropProtocol, Value: "a2a/1.0"},
		{Name: PropSourceFile, Value: filepath.ToSlash(relPath)},
		{Name: PropA2ACardSHA256, Value: hex.EncodeToString(sum[:])},
		{Name: PropA2AJWSStatus, Value: status},
	}
	if cardMeta.URL != "" {
		props = append(props, Property{Name: PropEndpoint, Value: cardMeta.URL})
	}
	report.Components = append(report.Components, Component{
		Type:       "service",
		Name:       cardMeta.Name,
		Version:    cardMeta.Version,
		Properties: props,
	})
	return nil
}

func collectPromptFiles(repoRoot string, explicit []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}

	for _, p := range explicit {
		add(p)
	}

	for _, candidate := range []string{"system_prompt.md", "SYSTEM_PROMPT.md", "system_prompt.txt"} {
		if _, err := os.Lstat(filepath.Join(repoRoot, candidate)); err == nil {
			add(candidate)
		}
	}
	for _, pattern := range []string{
		filepath.Join("prompts", "*.md"),
		filepath.Join("prompts", "*.txt"),
	} {
		matches, _ := filepath.Glob(filepath.Join(repoRoot, pattern))
		sort.Strings(matches)
		for _, m := range matches {
			if rel, err := filepath.Rel(repoRoot, m); err == nil {
				add(rel)
			}
		}
	}

	sort.Strings(out)
	return out
}
