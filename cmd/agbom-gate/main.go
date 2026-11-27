package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/secops/agbom-gate/internal/bom"
	"github.com/secops/agbom-gate/internal/canon"
	"github.com/secops/agbom-gate/internal/diff"
	"github.com/secops/agbom-gate/internal/mcpclient"
	"github.com/secops/agbom-gate/internal/proxy"
	"github.com/secops/agbom-gate/internal/reconcile"
	"github.com/secops/agbom-gate/internal/telemetry"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "keygen":
		runKeygen(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "diff":
		runDiff(os.Args[2:])
	case "reconcile":
		runReconcile(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `agbom-gate — Signed CycloneDX 1.6 AgBOM Scanner, PR Authority Diff, Reconciler & MCP Quarantine Proxy

Usage:
  agbom-gate keygen    --out <dir>
  agbom-gate scan      (--cmd <binary> [--args "..."] | --url <https://...> | --repo <dir> [--probe-discovered])
                       [--server-name <name>] [--allowed-tools "a,b"] [--step-up-tools "c"]
                       [--prompt-files "p1.md,p2.md"] [--a2a-pub-key <key>] [--require-signed-a2a=true]
                       [--tls-cert <crt> --tls-key <key> --tls-ca <ca>] [--obo-token-env <VAR> | --obo-token-cmd "..."]
                       [--nhi-principal <spiffe://...>] [--owner <email>]
                       [--sign-key <key>] --out agbom.json [--sig-out agbom.dsse.sig]
  agbom-gate diff      --base <base-agbom.json> --head <head-agbom.json>
  agbom-gate reconcile --agbom <agbom.json> [--sig <agbom.dsse.sig> --pub-key <agbom.pub>] --telemetry <path[,path2]>
  agbom-gate proxy     --agbom <agbom.json> --sig <agbom.dsse.sig> --pub-key <agbom.pub>
                       (--server-name <name> --cmd <binary> [--args "..."] |
                        --server-name <name> --listen <addr> --upstream-url <https://...> |
                        --listen <addr> --routes "srv1=https://...,srv2=https://...")
                       [--approval-webhook <https://...>] [--tls-cert <crt> --tls-key <key> --tls-ca <ca>]
                       [--obo-token-env <VAR> | --obo-token-cmd "..."]
                       [--telemetry-log <path>] [--otlp-endpoint <http://collector:4318>]
`)
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outDir := fs.String("out", ".", "Output directory for agbom.key and agbom.pub")
	_ = fs.Parse(args)

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fatal("mkdir out: %v", err)
	}
	pub, priv, err := bom.GenerateKeyPair()
	if err != nil {
		fatal("keygen: %v", err)
	}
	privPath := filepath.Join(*outDir, "agbom.key")
	pubPath := filepath.Join(*outDir, "agbom.pub")
	if err := os.WriteFile(privPath, bom.EncodeKey(priv), 0600); err != nil {
		fatal("write private key: %v", err)
	}
	if err := os.WriteFile(pubPath, bom.EncodeKey(pub), 0644); err != nil {
		fatal("write public key: %v", err)
	}
	fmt.Printf("Generated Ed25519 keypair:\n  private: %s\n  public:  %s\n", privPath, pubPath)
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	serverName := fs.String("server-name", "mcp-server", "Logical MCP server name")
	cmdBin := fs.String("cmd", "", "Stdio MCP server executable")
	cmdArgs := fs.String("args", "", "Space-separated arguments for MCP server")
	endpointURL := fs.String("url", "", "Streamable HTTP MCP endpoint URL")
	repoDir := fs.String("repo", "", "Optional repository root to discover MCP configs, lockfiles, data stores, A2A cards, and prompts")
	probeDiscovered := fs.Bool("probe-discovered", false, "Automatically probe discovered MCP targets in --repo to pin live tools/list SHA-256 hashes")
	promptFiles := fs.String("prompt-files", "", "Optional comma-separated system prompt file paths to hash")
	a2aPubKeyPath := fs.String("a2a-pub-key", "", "Public key (PEM/JWK/base64) to verify discovered A2A Agent Card JWS")
	requireSignedA2A := fs.Bool("require-signed-a2a", true, "Fail scan if a discovered A2A Agent Card is unsigned or has an invalid JWS")
	allowedTools := fs.String("allowed-tools", "", "Comma-separated allowlisted tool names")
	stepUpTools := fs.String("step-up-tools", "", "Comma-separated tools requiring HITL step-up")
	nhiPrincipal := fs.String("nhi-principal", "", "Optional SPIFFE/NHI principal recorded in AgBOM metadata")
	owner := fs.String("owner", "", "Optional owner email/team recorded in AgBOM metadata")
	tlsCert := fs.String("tls-cert", "", "Client mTLS certificate PEM path")
	tlsKey := fs.String("tls-key", "", "Client mTLS private key PEM path")
	tlsCA := fs.String("tls-ca", "", "Custom CA bundle PEM path")
	oboTokenEnv := fs.String("obo-token-env", "", "Environment variable name containing externally brokered OBO token")
	oboTokenCmd := fs.String("obo-token-cmd", "", "Command that prints a short-lived brokered OBO token to stdout")
	allowInsecureLocalhost := fs.Bool("allow-insecure-localhost", false, "Allow http:// endpoints strictly on localhost/127.0.0.1/::1")
	signKeyPath := fs.String("sign-key", "", "Optional Ed25519 private key to sign DSSE envelope")
	outPath := fs.String("out", "agbom.json", "Output CycloneDX 1.6 AgBOM file")
	sigOutPath := fs.String("sig-out", "agbom.dsse.sig", "Output DSSE signature envelope file")
	failOnLint := fs.Bool("fail-on-lint", true, "Fail scan if CRITICAL lint findings are detected")
	_ = fs.Parse(args)

	if *cmdBin == "" && *endpointURL == "" && *repoDir == "" {
		fatal("one of --cmd, --url, or --repo is required")
	}

	var components []bom.Component
	hasCritical := false
	totalTools := 0
	compositeSummary := ""

	baseHTTPCfg := mcpclient.HTTPConfig{
		TLSCertPath:            *tlsCert,
		TLSKeyPath:             *tlsKey,
		TLSCAPath:              *tlsCA,
		OBOToken:               resolveEnvToken(*oboTokenEnv),
		OBOTokenCmd:            *oboTokenCmd,
		AllowInsecureLocalhost: *allowInsecureLocalhost,
	}

	// 1. Direct live MCP scan (stdio or Streamable HTTP)
	if *cmdBin != "" || *endpointURL != "" {
		var rawTools []json.RawMessage
		var err error
		transport := "stdio"
		if *endpointURL != "" {
			transport = "streamable-http"
			if *tlsCert != "" {
				transport = "streamable-http-mtls"
			}
			cfg := baseHTTPCfg
			cfg.EndpointURL = *endpointURL
			rawTools, err = mcpclient.FetchToolsHTTP(context.Background(), cfg)
		} else {
			var splitArgs []string
			if strings.TrimSpace(*cmdArgs) != "" {
				splitArgs = strings.Fields(*cmdArgs)
			}
			rawTools, err = mcpclient.FetchToolsStdio(*cmdBin, splitArgs)
		}
		if err != nil {
			fatal("scan tools/list failed: %v", err)
		}

		findings, err := canon.LintToolSet(rawTools)
		if err != nil {
			fatal("lint toolset error: %v", err)
		}
		for _, f := range findings {
			fmt.Fprintf(os.Stderr, "[LINT %s] %s (%s @ %s): %s\n", f.Severity, f.Code, f.ToolName, f.FieldPath, f.Message)
			if f.Severity == "CRITICAL" {
				hasCritical = true
			}
		}

		compHash, pins, err := canon.HashToolSet(rawTools)
		if err != nil {
			fatal("canonical hashing failed: %v", err)
		}
		pinsJSON, _ := json.Marshal(pins)
		totalTools += len(pins)
		compositeSummary = compHash

		props := []bom.Property{
			{Name: bom.PropProtocol, Value: "mcp/2026-07"},
			{Name: bom.PropTransport, Value: transport},
			{Name: bom.PropTokenPassthru, Value: "forbidden-brokered-obo"},
			{Name: bom.PropAllowedTools, Value: *allowedTools},
			{Name: bom.PropStepUpTools, Value: *stepUpTools},
			{Name: bom.PropToolsListSHA256, Value: compHash},
			{Name: bom.PropToolPinsJSON, Value: string(pinsJSON)},
		}
		if *endpointURL != "" {
			props = append(props, bom.Property{Name: bom.PropEndpoint, Value: *endpointURL})
		}
		components = append(components, bom.Component{
			Type:       "service",
			Name:       *serverName,
			Version:    "1.0.0",
			Properties: props,
		})
	}

	// 2. Repo Discovery (MCP configs, lockfiles, data stores, A2A Agent Cards + JWS, system prompts)
	if *repoDir != "" {
		var a2aPub crypto.PublicKey
		if *a2aPubKeyPath != "" {
			rawPub, err := os.ReadFile(*a2aPubKeyPath)
			if err != nil {
				fatal("read a2a pub key: %v", err)
			}
			a2aPub, err = bom.LoadJWSVerifyKey(rawPub)
			if err != nil {
				fatal("parse a2a pub key: %v", err)
			}
		}
		var explicitPrompts []string
		for _, p := range strings.Split(*promptFiles, ",") {
			if tp := strings.TrimSpace(p); tp != "" {
				explicitPrompts = append(explicitPrompts, tp)
			}
		}
		report, err := bom.DiscoverRepo(bom.DiscoverOptions{
			RepoRoot:         *repoDir,
			PromptFiles:      explicitPrompts,
			A2APublicKey:     a2aPub,
			RequireSignedA2A: *requireSignedA2A,
		})
		if err != nil {
			fatal("repo discovery failed: %v", err)
		}
		for _, f := range report.Findings {
			fmt.Fprintf(os.Stderr, "[LINT %s] %s (%s @ %s): %s\n", f.Severity, f.Code, f.ToolName, f.FieldPath, f.Message)
			if f.Severity == "CRITICAL" {
				hasCritical = true
			}
		}

		// Optional live probing of discovered MCP targets with cross-server tool shadowing lint.
		if *probeDiscovered && len(report.MCPTargets) > 0 {
			probedTools := make(map[string][]json.RawMessage, len(report.MCPTargets))
			var allPeerNames []string
			for _, target := range report.MCPTargets {
				var rawTools []json.RawMessage
				var err error
				if target.Transport == "streamable-http" && target.URL != "" {
					cfg := baseHTTPCfg
					cfg.EndpointURL = target.URL
					rawTools, err = mcpclient.FetchToolsHTTP(context.Background(), cfg)
				} else if target.Command != "" {
					rawTools, err = mcpclient.FetchToolsStdio(target.Command, target.Args)
				} else {
					continue
				}
				if err != nil {
					fatal("probe discovered MCP server %q failed: %v", target.Name, err)
				}
				probedTools[target.Name] = rawTools
				for _, rt := range rawTools {
					var env struct {
						Name string `json:"name"`
					}
					if json.Unmarshal(rt, &env) == nil && env.Name != "" {
						allPeerNames = append(allPeerNames, env.Name)
					}
				}
			}

			for i := range report.Components {
				c := &report.Components[i]
				if c.Type != "service" {
					continue
				}
				rawTools, ok := probedTools[c.Name]
				if !ok {
					continue
				}
				findings, err := canon.LintToolSet(rawTools, allPeerNames...)
				if err != nil {
					fatal("lint probed server %q: %v", c.Name, err)
				}
				for _, f := range findings {
					fmt.Fprintf(os.Stderr, "[LINT %s] %s (%s @ %s): %s\n", f.Severity, f.Code, f.ToolName, f.FieldPath, f.Message)
					if f.Severity == "CRITICAL" {
						hasCritical = true
					}
				}
				compHash, pins, err := canon.HashToolSet(rawTools)
				if err != nil {
					fatal("hash probed server %q: %v", c.Name, err)
				}
				pinsJSON, _ := json.Marshal(pins)
				c.Version = "1.0.0"
				c.SetProperty(bom.PropToolsListSHA256, compHash)
				c.SetProperty(bom.PropToolPinsJSON, string(pinsJSON))
				totalTools += len(pins)
				compositeSummary = compHash
			}
		}

		components = append(components, report.Components...)
	}

	if hasCritical && *failOnLint {
		fatal("scan aborted: CRITICAL static injection/unicode findings detected")
	}

	var metaProps []bom.Property
	if *owner != "" {
		metaProps = append(metaProps, bom.Property{Name: bom.PropOwner, Value: *owner})
	}
	if *nhiPrincipal != "" {
		metaProps = append(metaProps, bom.Property{Name: bom.PropNHIPrincipal, Value: *nhiPrincipal})
	}

	doc := bom.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: bom.Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: &bom.Component{
				Type:    "application",
				Name:    "agbom-governed-agent",
				Version: "1.0.0",
			},
			Properties: metaProps,
		},
		Components: components,
	}

	docBytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fatal("marshal agbom: %v", err)
	}
	if err := os.WriteFile(*outPath, docBytes, 0644); err != nil {
		fatal("write agbom: %v", err)
	}
	if compositeSummary != "" {
		fmt.Printf("Wrote AgBOM (%d components, %d tools, composite sha256=%s) -> %s\n", len(components), totalTools, compositeSummary, *outPath)
	} else {
		fmt.Printf("Wrote AgBOM (%d discovered components) -> %s\n", len(components), *outPath)
	}

	if *signKeyPath != "" {
		rawKey, err := os.ReadFile(*signKeyPath)
		if err != nil {
			fatal("read sign key: %v", err)
		}
		privBytes, err := bom.DecodeKey(rawKey)
		if err != nil {
			fatal("decode sign key: %v", err)
		}
		env, err := bom.SignPayload(bom.PayloadTypeCycloneDX, docBytes, ed25519.PrivateKey(privBytes))
		if err != nil {
			fatal("sign agbom: %v", err)
		}
		envBytes, _ := bom.MarshalEnvelope(env)
		if err := os.WriteFile(*sigOutPath, envBytes, 0644); err != nil {
			fatal("write dsse sig: %v", err)
		}
		fmt.Printf("Signed DSSE envelope -> %s\n", *sigOutPath)
	}
}

func runDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	basePath := fs.String("base", "", "Base agbom.json path")
	headPath := fs.String("head", "", "Head agbom.json path")
	_ = fs.Parse(args)

	if *basePath == "" || *headPath == "" {
		fatal("--base and --head are required")
	}
	baseBOM := loadBOM(*basePath)
	headBOM := loadBOM(*headPath)

	res := diff.Compare(baseBOM, headBOM)
	fmt.Print(res.Markdown)
	os.Exit(res.ExitCode)
}

func runReconcile(args []string) {
	fs := flag.NewFlagSet("reconcile", flag.ExitOnError)
	agbomPath := fs.String("agbom", "agbom.json", "Path to declared CycloneDX AgBOM")
	sigPath := fs.String("sig", "", "Optional DSSE signature envelope to verify before reconciling")
	pubKeyPath := fs.String("pub-key", "", "Optional Ed25519 public key (required if --sig is set)")
	telemetryPaths := fs.String("telemetry", "", "Comma-separated paths to ACS NDJSON or OTLP JSON trace files")
	_ = fs.Parse(args)

	if *telemetryPaths == "" {
		fatal("--telemetry is required")
	}

	agbomBytes, err := os.ReadFile(*agbomPath)
	if err != nil {
		fatal("read agbom: %v", err)
	}
	if *sigPath != "" || *pubKeyPath != "" {
		if *sigPath == "" || *pubKeyPath == "" {
			fatal("both --sig and --pub-key must be provided when verifying signature")
		}
		verifySignedBytes(agbomBytes, *sigPath, *pubKeyPath)
	}

	var doc bom.BOM
	if err := json.Unmarshal(agbomBytes, &doc); err != nil {
		fatal("parse agbom json: %v", err)
	}

	var allObs []reconcile.Observation
	for _, p := range strings.Split(*telemetryPaths, ",") {
		path := strings.TrimSpace(p)
		if path == "" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			fatal("read telemetry %s: %v", path, err)
		}
		obs, err := reconcile.ParseTelemetry(raw)
		if err != nil {
			fatal("parse telemetry %s: %v", path, err)
		}
		allObs = append(allObs, obs...)
	}

	res := reconcile.Reconcile(&doc, allObs)
	fmt.Print(res.Markdown)
	os.Exit(res.ExitCode)
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	agbomPath := fs.String("agbom", "agbom.json", "Path to signed CycloneDX AgBOM")
	sigPath := fs.String("sig", "agbom.dsse.sig", "Path to DSSE signature envelope")
	pubKeyPath := fs.String("pub-key", "agbom.pub", "Path to pinned Ed25519 public key")
	serverName := fs.String("server-name", "", "MCP server component name inside AgBOM (single-server mode)")
	cmdBin := fs.String("cmd", "", "Upstream stdio MCP server binary")
	cmdArgs := fs.String("args", "", "Space-separated arguments for upstream MCP server")
	listenAddr := fs.String("listen", "", "Listen address (e.g. 127.0.0.1:8080) for Streamable HTTP proxy/gateway mode")
	upstreamURL := fs.String("upstream-url", "", "Upstream Streamable HTTP MCP endpoint URL (single-server HTTP mode)")
	routesSpec := fs.String("routes", "", "Comma-separated multi-server gateway routes: name1=https://...,name2=https://...")
	approvalWebhook := fs.String("approval-webhook", "", "Optional HTTPS/HTTP webhook URL for HITL step-up approval callbacks")
	tlsCert := fs.String("tls-cert", "", "Client mTLS certificate PEM path for upstream HTTPS")
	tlsKey := fs.String("tls-key", "", "Client mTLS private key PEM path for upstream HTTPS")
	tlsCA := fs.String("tls-ca", "", "Custom CA bundle PEM path for upstream HTTPS")
	oboTokenEnv := fs.String("obo-token-env", "", "Environment variable name containing externally brokered OBO token")
	oboTokenCmd := fs.String("obo-token-cmd", "", "Command that prints a short-lived brokered OBO token to stdout")
	allowInsecureLocalhost := fs.Bool("allow-insecure-localhost", false, "Allow http:// upstream strictly on localhost/127.0.0.1/::1")
	telemetryLog := fs.String("telemetry-log", "", "Optional file path for ACS DFIR NDJSON logs (defaults to stderr)")
	otlpEndpoint := fs.String("otlp-endpoint", "", "Optional OTLP/HTTP endpoint (defaults to OTEL_EXPORTER_OTLP_ENDPOINT)")
	_ = fs.Parse(args)

	gatewayMode := strings.TrimSpace(*routesSpec) != ""
	httpMode := gatewayMode || *listenAddr != "" || *upstreamURL != ""
	if gatewayMode && *listenAddr == "" {
		fatal("--listen is required with --routes")
	}
	if !gatewayMode && *serverName == "" {
		fatal("--server-name is required (or use --routes for multi-server HTTP gateway mode)")
	}
	if httpMode && !gatewayMode && (*listenAddr == "" || *upstreamURL == "") {
		fatal("both --listen and --upstream-url are required for single-server Streamable HTTP proxy mode")
	}
	if !httpMode && *cmdBin == "" {
		fatal("either --cmd (stdio mode), --listen + --upstream-url, or --listen + --routes is required")
	}

	agbomBytes, err := os.ReadFile(*agbomPath)
	if err != nil {
		fatal("read agbom: %v", err)
	}
	verifySignedBytes(agbomBytes, *sigPath, *pubKeyPath)

	var doc bom.BOM
	if err := json.Unmarshal(agbomBytes, &doc); err != nil {
		fatal("parse agbom json: %v", err)
	}
	nhiPrincipal, _ := doc.GetMetadataProperty(bom.PropNHIPrincipal)

	var logWriter io.Writer = os.Stderr
	if *telemetryLog != "" {
		f, err := os.OpenFile(*telemetryLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fatal("open telemetry log: %v", err)
		}
		defer f.Close()
		logWriter = f
	}

	logger := telemetry.NewLogger(logWriter)
	ep := strings.TrimSpace(*otlpEndpoint)
	if ep == "" {
		ep = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	if ep != "" {
		logger.WithSink(telemetry.NewOTLPExporter(ep, "agbom-gate"))
		defer func() { _ = logger.Close() }()
	}

	var approvalHook proxy.ApprovalHook
	if strings.TrimSpace(*approvalWebhook) != "" {
		if err := mcpclient.ValidateEndpointURL(*approvalWebhook, *allowInsecureLocalhost); err != nil {
			fatal("invalid --approval-webhook: %v", err)
		}
		approvalHook = proxy.NewWebhookApprovalHook(*approvalWebhook, nil)
	}

	baseHTTPCfg := mcpclient.HTTPConfig{
		TLSCertPath:            *tlsCert,
		TLSKeyPath:             *tlsKey,
		TLSCAPath:              *tlsCA,
		OBOToken:               resolveEnvToken(*oboTokenEnv),
		OBOTokenCmd:            *oboTokenCmd,
		AllowInsecureLocalhost: *allowInsecureLocalhost,
	}

	if gatewayMode {
		routes := make(map[string]mcpclient.HTTPConfig)
		for _, item := range strings.Split(*routesSpec, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
				fatal("invalid --routes entry %q (expected name=url)", item)
			}
			cfg := baseHTTPCfg
			cfg.EndpointURL = strings.TrimSpace(parts[1])
			routes[strings.TrimSpace(parts[0])] = cfg
		}
		gw, err := proxy.NewHTTPGateway(&doc, logger, routes, approvalHook)
		if err != nil {
			fatal("init http gateway: %v", err)
		}
		fmt.Fprintf(os.Stderr, "agbom-gate multi-server HTTP gateway listening on %s (%d routes)\n", *listenAddr, len(routes))
		if err := http.ListenAndServe(*listenAddr, gw); err != nil {
			fatal("http gateway error: %v", err)
		}
		return
	}

	svc := doc.FindMCPService(*serverName)
	if svc == nil {
		fatal("service %q not found in signed AgBOM", *serverName)
	}

	if httpMode {
		cfg := baseHTTPCfg
		cfg.EndpointURL = *upstreamURL
		hp, err := proxy.NewHTTPQuarantineProxy(svc, logger, cfg)
		if err != nil {
			fatal("init http proxy: %v", err)
		}
		hp.SetNHIPrincipal(nhiPrincipal)
		if approvalHook != nil {
			hp.SetApprovalHook(approvalHook)
		}
		mux := http.NewServeMux()
		mux.Handle("/mcp", hp)
		mux.Handle("/", hp)
		fmt.Fprintf(os.Stderr, "agbom-gate HTTP quarantine proxy listening on %s -> %s (server=%s)\n", *listenAddr, *upstreamURL, *serverName)
		if err := http.ListenAndServe(*listenAddr, mux); err != nil {
			fatal("http proxy server error: %v", err)
		}
		return
	}

	qp, err := proxy.NewQuarantineProxy(svc, logger)
	if err != nil {
		fatal("init proxy: %v", err)
	}
	qp.SetNHIPrincipal(nhiPrincipal)
	if approvalHook != nil {
		qp.SetApprovalHook(approvalHook)
	}

	var splitArgs []string
	if strings.TrimSpace(*cmdArgs) != "" {
		splitArgs = strings.Fields(*cmdArgs)
	}
	cmd := exec.Command(*cmdBin, splitArgs...)
	upIn, err := cmd.StdinPipe()
	if err != nil {
		fatal("upstream stdin pipe: %v", err)
	}
	upOut, err := cmd.StdoutPipe()
	if err != nil {
		fatal("upstream stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fatal("start upstream mcp server: %v", err)
	}
	defer func() {
		_ = upIn.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	if err := qp.Serve(os.Stdin, os.Stdout, upIn, upOut); err != nil {
		fatal("proxy loop error: %v", err)
	}
}

func verifySignedBytes(agbomBytes []byte, sigPath, pubKeyPath string) {
	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		fatal("read dsse sig: %v", err)
	}
	pubRaw, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fatal("read pub key: %v", err)
	}
	pubKeyBytes, err := bom.DecodeKey(pubRaw)
	if err != nil {
		fatal("decode pub key: %v", err)
	}
	var env bom.DSSEEnvelope
	if err := json.Unmarshal(sigBytes, &env); err != nil {
		fatal("parse dsse envelope: %v", err)
	}
	if err := bom.VerifyEnvelope(&env, agbomBytes, ed25519.PublicKey(pubKeyBytes)); err != nil {
		fatal("FAIL-CLOSED BOOT ABORT: %v", err)
	}
}

func resolveEnvToken(envName string) string {
	envName = strings.TrimSpace(envName)
	if envName == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func loadBOM(path string) *bom.BOM {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal("read %s: %v", path, err)
	}
	var doc bom.BOM
	if err := json.Unmarshal(b, &doc); err != nil {
		fatal("parse %s: %v", path, err)
	}
	return &doc
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
