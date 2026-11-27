package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/secops/agbom-gate/internal/bom"
	"github.com/secops/agbom-gate/internal/canon"
	"github.com/secops/agbom-gate/internal/mcpclient"
	"github.com/secops/agbom-gate/internal/telemetry"
)

// HTTPQuarantineProxy is a fail-closed MCP Streamable HTTP + SSE quarantine proxy.
// It shares the core QuarantineProxy policy engine (two-level JCS SHA-256 verification,
// allowed_tools filtering, HITL step-up blocking/webhook, pinned inputSchema argument validation),
// enforces no token passthrough, and intercepts SSE notifications/tools/list_changed.
type HTTPQuarantineProxy struct {
	core   *QuarantineProxy
	cfg    mcpclient.HTTPConfig
	client *http.Client

	sessionMu sync.Mutex
	sessionID string
	reqIDMu   sync.Mutex
	reqIDSeq  int
}

// NewHTTPQuarantineProxy builds a Streamable HTTP Quarantine Proxy backed by a signed AgBOM service.
func NewHTTPQuarantineProxy(svc *bom.Component, logger *telemetry.Logger, cfg mcpclient.HTTPConfig) (*HTTPQuarantineProxy, error) {
	if err := mcpclient.ValidateEndpointURL(cfg.EndpointURL, cfg.AllowInsecureLocalhost); err != nil {
		return nil, err
	}
	client, err := mcpclient.BuildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	core, err := NewQuarantineProxy(svc, logger)
	if err != nil {
		return nil, err
	}
	return &HTTPQuarantineProxy{
		core:     core,
		cfg:      cfg,
		client:   client,
		reqIDSeq: 800000,
	}, nil
}

// SetNHIPrincipal sets the agbom:nhi_principal identity attached to ACS/OTLP telemetry events.
func (p *HTTPQuarantineProxy) SetNHIPrincipal(principal string) {
	p.core.SetNHIPrincipal(principal)
}

// SetApprovalHook configures an optional external HITL step-up approval hook.
func (p *HTTPQuarantineProxy) SetApprovalHook(hook ApprovalHook) {
	p.core.SetApprovalHook(hook)
}

// State returns the current quarantine state machine state.
func (p *HTTPQuarantineProxy) State() State {
	return p.core.State()
}

// HTTPGateway multiplexes multiple independent HTTPQuarantineProxy instances under /mcp/{server-name},
// preserving strict per-server blast-radius isolation inside a single gateway process.
type HTTPGateway struct {
	proxies      map[string]*HTTPQuarantineProxy
	logger       *telemetry.Logger
	nhiPrincipal string
}

// NewHTTPGateway constructs a multi-server Streamable HTTP gateway from a signed AgBOM
// and a map of logical server name -> upstream HTTPConfig.
func NewHTTPGateway(doc *bom.BOM, logger *telemetry.Logger, routes map[string]mcpclient.HTTPConfig, approvalHook ApprovalHook) (*HTTPGateway, error) {
	if doc == nil {
		return nil, errors.New("nil signed AgBOM")
	}
	if len(routes) == 0 {
		return nil, errors.New("at least one server route is required")
	}
	nhi, _ := doc.GetMetadataProperty(bom.PropNHIPrincipal)
	proxies := make(map[string]*HTTPQuarantineProxy, len(routes))
	for name, cfg := range routes {
		svc := doc.FindMCPService(name)
		if svc == nil {
			return nil, fmt.Errorf("route server %q not found in signed AgBOM", name)
		}
		hp, err := NewHTTPQuarantineProxy(svc, logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("init route %q: %w", name, err)
		}
		hp.SetNHIPrincipal(nhi)
		if approvalHook != nil {
			hp.SetApprovalHook(approvalHook)
		}
		proxies[name] = hp
	}
	return &HTTPGateway{
		proxies:      proxies,
		logger:       logger,
		nhiPrincipal: nhi,
	}, nil
}

// ProxyFor returns the isolated HTTPQuarantineProxy for a given logical server name.
func (g *HTTPGateway) ProxyFor(serverName string) *HTTPQuarantineProxy {
	return g.proxies[serverName]
}

// ServeHTTP dispatches /mcp/{server-name} to the matching isolated HTTPQuarantineProxy.
// Undeclared server names fail closed with HTTP 404 and JSON-RPC -32098.
func (g *HTTPGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/mcp/")
	serverName := strings.SplitN(strings.TrimPrefix(trimmed, "/"), "/", 2)[0]
	if serverName == "" {
		w.WriteHeader(http.StatusNotFound)
		writeHTTPRPCError(w, json.RawMessage("null"), ErrCodeToolBlocked, "UNDECLARED_MCP_SERVER: missing server name in /mcp/{server-name}")
		return
	}
	hp, ok := g.proxies[serverName]
	if !ok {
		g.logger.Emit(telemetry.ACSEvent{
			EventType:    "agbom/tool_blocked",
			Severity:     "WARN",
			ServerName:   serverName,
			NHIPrincipal: g.nhiPrincipal,
			TraceParent:  r.Header.Get("traceparent"),
			Reason:       "undeclared MCP server requested at HTTP gateway",
		})
		w.WriteHeader(http.StatusNotFound)
		writeHTTPRPCError(w, json.RawMessage("null"), ErrCodeToolBlocked, fmt.Sprintf("UNDECLARED_MCP_SERVER: %s", serverName))
		return
	}
	hp.ServeHTTP(w, r)
}

// ServeHTTP handles MCP Streamable HTTP POST (JSON-RPC), GET (SSE notifications), and DELETE (session end).
func (p *HTTPQuarantineProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceParent := r.Header.Get("traceparent")

	// Security Invariant #7: Never pass through raw client Authorization headers upstream.
	if r.Header.Get("Authorization") != "" {
		p.core.logger.Emit(telemetry.ACSEvent{
			EventType:    "agbom/tool_blocked",
			Severity:     "WARN",
			ServerName:   p.core.serverName,
			NHIPrincipal: p.core.getNHIPrincipal(),
			TraceParent:  traceParent,
			Reason:       "inbound client Authorization header stripped (token passthrough forbidden)",
		})
	}

	switch r.Method {
	case http.MethodPost:
		p.handlePost(w, r, traceParent)
	case http.MethodGet:
		p.handleSSE(w, r, traceParent)
	case http.MethodDelete:
		p.handleDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *HTTPQuarantineProxy) handlePost(w http.ResponseWriter, r *http.Request, traceParent string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
	if err != nil {
		writeHTTPRPCError(w, json.RawMessage("null"), -32700, "read request body: "+err.Error())
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		writeHTTPRPCError(w, json.RawMessage("null"), -32700, "empty JSON-RPC payload")
		return
	}
	if trimmed[0] == '[' {
		writeHTTPRPCError(w, json.RawMessage("null"), -32600, "invalid request: JSON-RPC batch arrays are not supported")
		return
	}
	if _, err := canon.DecodeStrictJSON(trimmed); err != nil {
		writeHTTPRPCError(w, json.RawMessage("null"), -32700, "invalid JSON-RPC payload: "+err.Error())
		return
	}
	var msg rpcMsg
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		writeHTTPRPCError(w, json.RawMessage("null"), -32700, "invalid JSON-RPC payload")
		return
	}

	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		p.setSessionID(sid)
	}

	if len(msg.ID) == 0 || string(msg.ID) == "null" {
		if p.core.State() == StateQuarantined {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp, err := p.forwardRawPost(r.Context(), trimmed, traceParent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_ = resp.Body.Close()
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if p.core.State() == StateQuarantined {
		writeHTTPRPCError(w, msg.ID, ErrCodeQuarantined, "MCP_SERVER_QUARANTINED_HASH_MISMATCH")
		return
	}

	switch msg.Method {
	case "initialize":
		respMsg, sid, err := p.doUpstreamRPC(r.Context(), msg, traceParent)
		if err != nil {
			writeHTTPRPCError(w, msg.ID, -32603, err.Error())
			return
		}
		if sid != "" {
			w.Header().Set("Mcp-Session-Id", sid)
		}
		writeHTTPRPC(w, respMsg)

	case "tools/list":
		filtered, err := p.verifyAndFilterHTTP(r.Context(), traceParent)
		if err != nil {
			writeHTTPRPCError(w, msg.ID, ErrCodeQuarantined, "MCP_SERVER_QUARANTINED_HASH_MISMATCH: "+err.Error())
			return
		}
		resBytes, _ := json.Marshal(map[string]any{"tools": filtered})
		writeHTTPRPC(w, rpcMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  resBytes,
		})

	case "tools/call":
		cleanParams, code, errMsg, ok := p.core.AuthorizeToolCall(r.Context(), msg.Params, traceParent)
		if !ok {
			writeHTTPRPCError(w, msg.ID, code, errMsg)
			return
		}
		msg.Params = cleanParams
		respMsg, sid, err := p.doUpstreamRPC(r.Context(), msg, traceParent)
		if err != nil {
			writeHTTPRPCError(w, msg.ID, -32603, err.Error())
			return
		}
		if sid != "" {
			w.Header().Set("Mcp-Session-Id", sid)
		}
		writeHTTPRPC(w, respMsg)

	default:
		respMsg, sid, err := p.doUpstreamRPC(r.Context(), msg, traceParent)
		if err != nil {
			writeHTTPRPCError(w, msg.ID, -32603, err.Error())
			return
		}
		if sid != "" {
			w.Header().Set("Mcp-Session-Id", sid)
		}
		writeHTTPRPC(w, respMsg)
	}
}

func (p *HTTPQuarantineProxy) handleSSE(w http.ResponseWriter, r *http.Request, traceParent string) {
	if p.core.State() == StateQuarantined {
		w.WriteHeader(http.StatusForbidden)
		writeHTTPRPCError(w, json.RawMessage("null"), ErrCodeQuarantined, "MCP_SERVER_QUARANTINED_HASH_MISMATCH")
		return
	}

	// Cancel the open SSE stream immediately if any concurrent request quarantines this server.
	sseCtx, cancelSSE := context.WithCancel(r.Context())
	defer cancelSSE()
	go func() {
		select {
		case <-p.core.QuarantinedChan():
			cancelSSE()
		case <-sseCtx.Done():
		}
	}()

	upReq, err := http.NewRequestWithContext(sseCtx, http.MethodGet, p.cfg.EndpointURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	upReq.Header.Set("Accept", "text/event-stream")
	if sid := p.getSessionID(); sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}
	if err := p.applyUpstreamAuth(sseCtx, upReq); err != nil {
		http.Error(w, "upstream auth failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	upResp, err := p.client.Do(upReq)
	if err != nil {
		http.Error(w, "upstream SSE connect failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	if upResp.StatusCode < 200 || upResp.StatusCode >= 300 {
		http.Error(w, fmt.Sprintf("upstream SSE status %d", upResp.StatusCode), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	scanner := bufio.NewScanner(upResp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var eventType string
	var dataLines []string

	flushEvent := func() bool {
		if len(dataLines) == 0 && eventType == "" {
			return true
		}
		payload := strings.Join(dataLines, "\n")
		evName := eventType
		eventType = ""
		dataLines = dataLines[:0]

		var notif rpcMsg
		if json.Unmarshal([]byte(payload), &notif) == nil && notif.Method == "notifications/tools/list_changed" {
			// CRITICAL: Intercept SSE list_changed; re-verify upstream tools/list before forwarding.
			if _, err := p.verifyAndFilterHTTP(r.Context(), traceParent); err != nil {
				return false
			}
		}

		if p.core.State() == StateQuarantined {
			return false
		}
		if evName != "" {
			_, _ = fmt.Fprintf(w, "event: %s\n", evName)
		}
		for _, dl := range strings.Split(payload, "\n") {
			_, _ = fmt.Fprintf(w, "data: %s\n", dl)
		}
		_, _ = fmt.Fprint(w, "\n")
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if !flushEvent() {
				return
			}
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	_ = flushEvent()
}

func (p *HTTPQuarantineProxy) handleDelete(w http.ResponseWriter, r *http.Request) {
	reqCtx, cancel := context.WithTimeout(r.Context(), p.cfg.EffectiveRPCTimeout())
	defer cancel()

	upReq, err := http.NewRequestWithContext(reqCtx, http.MethodDelete, p.cfg.EndpointURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sid := p.getSessionID(); sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}
	if err := p.applyUpstreamAuth(reqCtx, upReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp, err := p.client.Do(upReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

func (p *HTTPQuarantineProxy) verifyAndFilterHTTP(ctx context.Context, traceParent string) ([]json.RawMessage, error) {
	return p.core.VerifyWithFetcher(traceParent, func() ([]json.RawMessage, error) {
		var allTools []json.RawMessage
		var cursor string
		completed := false
		for page := 0; page < MaxPages; page++ {
			paramsBytes := []byte("{}")
			if cursor != "" {
				paramsBytes, _ = json.Marshal(map[string]any{"cursor": cursor})
			}
			respMsg, _, err := p.doUpstreamRPC(ctx, rpcMsg{
				JSONRPC: "2.0",
				ID:      p.nextReqID(),
				Method:  "tools/list",
				Params:  paramsBytes,
			}, traceParent)
			if err != nil {
				return nil, fmt.Errorf("upstream tools/list error: %w", err)
			}
			if respMsg.Error != nil {
				return nil, errors.New(respMsg.Error.Message)
			}
			var listRes struct {
				Tools      []json.RawMessage `json:"tools"`
				NextCursor string            `json:"nextCursor"`
			}
			if err := json.Unmarshal(respMsg.Result, &listRes); err != nil {
				return nil, fmt.Errorf("malformed tools/list json: %w", err)
			}
			allTools = append(allTools, listRes.Tools...)
			if listRes.NextCursor == "" {
				completed = true
				break
			}
			cursor = listRes.NextCursor
		}
		if !completed {
			return nil, errors.New("tools/list exceeded max pagination limit (50 pages)")
		}
		return allTools, nil
	})
}

func (p *HTTPQuarantineProxy) doUpstreamRPC(ctx context.Context, req rpcMsg, traceParent string) (rpcMsg, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, p.cfg.EffectiveRPCTimeout())
	defer cancel()

	body, err := json.Marshal(req)
	if err != nil {
		return rpcMsg{}, "", err
	}
	resp, err := p.forwardRawPost(reqCtx, body, traceParent)
	if err != nil {
		return rpcMsg{}, "", err
	}
	defer resp.Body.Close()

	sid := resp.Header.Get("Mcp-Session-Id")
	if sid != "" {
		p.setSessionID(sid)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		rawErr, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return rpcMsg{}, sid, fmt.Errorf("upstream HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawErr)))
	}

	parsed, err := readProxyRPCFromHTTP(resp)
	if err != nil {
		return rpcMsg{}, sid, err
	}
	return parsed, sid, nil
}

func (p *HTTPQuarantineProxy) forwardRawPost(ctx context.Context, body []byte, traceParent string) (*http.Response, error) {
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json, text/event-stream")
	if sid := p.getSessionID(); sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}
	if traceParent != "" {
		upReq.Header.Set("traceparent", traceParent)
	}
	if err := p.applyUpstreamAuth(ctx, upReq); err != nil {
		return nil, err
	}
	return p.client.Do(upReq)
}

func (p *HTTPQuarantineProxy) applyUpstreamAuth(ctx context.Context, req *http.Request) error {
	req.Header.Del("Authorization")
	tok, err := mcpclient.ResolveOBOToken(ctx, p.cfg)
	if err != nil {
		return err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return nil
}

func readProxyRPCFromHTTP(resp *http.Response) (rpcMsg, error) {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
		var dataLines []string
		flush := func() (rpcMsg, bool) {
			if len(dataLines) == 0 {
				return rpcMsg{}, false
			}
			payload := strings.Join(dataLines, "\n")
			dataLines = dataLines[:0]
			var m rpcMsg
			if json.Unmarshal([]byte(payload), &m) == nil && len(m.ID) > 0 && string(m.ID) != "null" {
				return m, true
			}
			return rpcMsg{}, false
		}
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				if m, ok := flush(); ok {
					return m, nil
				}
				continue
			}
			if strings.HasPrefix(line, "data:") {
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		if err := scanner.Err(); err != nil {
			return rpcMsg{}, err
		}
		if m, ok := flush(); ok {
			return m, nil
		}
		return rpcMsg{}, io.EOF
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return rpcMsg{}, err
	}
	var m rpcMsg
	if err := json.Unmarshal(raw, &m); err != nil {
		return rpcMsg{}, fmt.Errorf("decode upstream json-rpc: %w", err)
	}
	return m, nil
}

func (p *HTTPQuarantineProxy) nextReqID() json.RawMessage {
	p.reqIDMu.Lock()
	p.reqIDSeq++
	id := p.reqIDSeq
	p.reqIDMu.Unlock()
	return json.RawMessage(fmt.Sprintf("%d", id))
}

func (p *HTTPQuarantineProxy) setSessionID(sid string) {
	p.sessionMu.Lock()
	p.sessionID = sid
	p.sessionMu.Unlock()
}

func (p *HTTPQuarantineProxy) getSessionID() string {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()
	return p.sessionID
}

func writeHTTPRPC(w http.ResponseWriter, msg rpcMsg) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(msg)
	_, _ = w.Write(append(b, '\n'))
}

func writeHTTPRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	writeHTTPRPC(w, rpcMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcErr{Code: code, Message: message},
	})
}
