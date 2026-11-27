package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// HTTPConfig configures a Streamable HTTP MCP connection with mTLS and external OBO auth.
type HTTPConfig struct {
	EndpointURL            string
	TLSCertPath            string
	TLSKeyPath             string
	TLSCAPath              string
	OBOToken               string
	OBOTokenCmd            string
	AllowInsecureLocalhost bool
	Timeout                time.Duration
	HTTPClient             *http.Client // Optional override (primarily for tests)
}

// ValidateEndpointURL enforces HTTPS unless AllowInsecureLocalhost is set for loopback hosts.
func ValidateEndpointURL(rawURL string, allowInsecureLocalhost bool) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid upstream MCP URL %q", rawURL)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		host := strings.ToLower(u.Hostname())
		if allowInsecureLocalhost && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
			return nil
		}
		return fmt.Errorf("refusing insecure http:// upstream %q (use https:// or --allow-insecure-localhost for loopback)", rawURL)
	default:
		return fmt.Errorf("unsupported MCP URL scheme %q (expected https)", u.Scheme)
	}
}

// BuildHTTPClient constructs an *http.Client enforcing TLS 1.2+ and optional mTLS/custom CA.
func BuildHTTPClient(cfg HTTPConfig) (*http.Client, error) {
	if cfg.EndpointURL != "" {
		if err := ValidateEndpointURL(cfg.EndpointURL, cfg.AllowInsecureLocalhost); err != nil {
			return nil, err
		}
	}
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient, nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.TLSCertPath != "" || cfg.TLSKeyPath != "" {
		if cfg.TLSCertPath == "" || cfg.TLSKeyPath == "" {
			return nil, errors.New("both --tls-cert and --tls-key must be provided for mTLS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load mTLS client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSCAPath != "" {
		caPEM, err := os.ReadFile(cfg.TLSCAPath)
		if err != nil {
			return nil, fmt.Errorf("read TLS CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse TLS CA bundle %q: no valid PEM certificates found", cfg.TLSCAPath)
		}
		tlsCfg.RootCAs = pool
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}

// ResolveOBOToken returns an externally brokered On-Behalf-Of bearer token if configured.
// Raw client tokens are never passed through.
func ResolveOBOToken(ctx context.Context, cfg HTTPConfig) (string, error) {
	if tok := strings.TrimSpace(cfg.OBOToken); tok != "" {
		return tok, nil
	}
	if cmdLine := strings.TrimSpace(cfg.OBOTokenCmd); cmdLine != "" {
		parts := strings.Fields(cmdLine)
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("obo token broker command failed: %w", err)
		}
		tok := strings.TrimSpace(string(out))
		if tok == "" {
			return "", errors.New("obo token broker command returned empty token")
		}
		return tok, nil
	}
	return "", nil
}

// FetchToolsHTTP connects to a Streamable HTTP MCP server, completes initialize,
// and retrieves all pages of tools/list (supporting both JSON and SSE responses).
func FetchToolsHTTP(ctx context.Context, cfg HTTPConfig) ([]json.RawMessage, error) {
	client, err := BuildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	var sessionID string
	postRPC := func(req rpcRequest) (*rpcResponse, error) {
		body, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EndpointURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			httpReq.Header.Set("Mcp-Session-Id", sessionID)
		}
		tok, err := ResolveOBOToken(ctx, cfg)
		if err != nil {
			return nil, err
		}
		if tok != "" {
			httpReq.Header.Set("Authorization", "Bearer "+tok)
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			sessionID = sid
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return nil, fmt.Errorf("upstream HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
		}
		return ReadJSONRPCResponse(resp)
	}

	// 1. initialize
	if _, err := postRPC(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": "2026-07-28",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "agbom-gate-scanner", "version": "0.2.0"},
		},
	}); err != nil {
		return nil, fmt.Errorf("initialize failed: %w", err)
	}

	// 2. paginated tools/list
	var allTools []json.RawMessage
	var cursor string
	reqID := 2
	for page := 0; page < MaxPaginationPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		resp, err := postRPC(rpcRequest{
			JSONRPC: "2.0",
			ID:      reqID,
			Method:  "tools/list",
			Params:  params,
		})
		reqID++
		if err != nil {
			return nil, fmt.Errorf("tools/list page %d failed: %w", page, err)
		}

		var listRes struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := json.Unmarshal(resp.Result, &listRes); err != nil {
			return nil, fmt.Errorf("decode tools/list result: %w", err)
		}
		allTools = append(allTools, listRes.Tools...)
		if listRes.NextCursor == "" {
			return allTools, nil
		}
		cursor = listRes.NextCursor
	}
	return nil, errors.New("tools/list exceeded max pagination limit (50 pages)")
}

// ReadJSONRPCResponse extracts a JSON-RPC response from either application/json or text/event-stream.
func ReadJSONRPCResponse(resp *http.Response) (*rpcResponse, error) {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		return readJSONRPCFromSSE(resp.Body)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, err
	}
	var rpcResp rpcResponse
	if err := json.Unmarshal(raw, &rpcResp); err != nil {
		return nil, fmt.Errorf("decode json-rpc response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("mcp rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return &rpcResp, nil
}

func readJSONRPCFromSSE(r io.Reader) (*rpcResponse, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var dataLines []string
	flush := func() (*rpcResponse, bool, error) {
		if len(dataLines) == 0 {
			return nil, false, nil
		}
		payload := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		var rpcResp rpcResponse
		if err := json.Unmarshal([]byte(payload), &rpcResp); err != nil {
			return nil, false, nil
		}
		// Ignore server notifications inside the SSE response stream.
		if len(rpcResp.ID) == 0 || string(rpcResp.ID) == "null" {
			return nil, false, nil
		}
		if rpcResp.Error != nil {
			return nil, true, fmt.Errorf("mcp rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
		}
		return &rpcResp, true, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if resp, done, err := flush(); done || err != nil {
				return resp, err
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if resp, done, err := flush(); done || err != nil {
		return resp, err
	}
	return nil, io.EOF
}
