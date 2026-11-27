package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/secops/agbom-gate/internal/bom"
	"github.com/secops/agbom-gate/internal/canon"
	"github.com/secops/agbom-gate/internal/telemetry"
)

const (
	ErrCodeQuarantined = -32099
	ErrCodeToolBlocked = -32098
	ErrCodeStepUpReq   = -32097
	ErrCodeInvalidArgs = -32096
	MaxPages           = 50

	defaultUpstreamTimeout = 30 * time.Second
)

type State string

const (
	StateUnverified  State = "UNVERIFIED"
	StateVerifying   State = "VERIFYING"
	StateActive      State = "ACTIVE"
	StateQuarantined State = "QUARANTINED"
)

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// QuarantineProxy sits between an AI client and a single upstream MCP server over stdio pipes,
// and also serves as the core fail-closed policy engine shared with HTTPQuarantineProxy.
type QuarantineProxy struct {
	serverName      string
	nhiPrincipal    string
	expectedHash    string
	expectedPins    []canon.ToolPin
	allowAllTools   bool
	allowedTools    map[string]struct{}
	stepUpTools     map[string]struct{}
	approvalHook    ApprovalHook
	upstreamTimeout time.Duration
	logger          *telemetry.Logger

	stateMu         sync.Mutex
	state           State
	pinnedSchemas   map[string]*CompiledSchema
	verifyMu        sync.Mutex
	clientWriteMu   sync.Mutex
	clientWrite     io.Writer
	upstreamWriteMu sync.Mutex
	upstreamWrite   io.Writer
	pendingMu       sync.Mutex
	pending         map[string]chan rpcMsg
	upstreamIDSeq   uint64
	upClosed        chan struct{}
	upCloseOnce     sync.Once
	quarantinedCh   chan struct{}
	quarantineOnce  sync.Once
}

func NewQuarantineProxy(svc *bom.Component, logger *telemetry.Logger) (*QuarantineProxy, error) {
	if svc == nil {
		return nil, errors.New("nil service component in AgBOM")
	}
	expectedHash, ok := svc.GetProperty(bom.PropToolsListSHA256)
	if !ok || expectedHash == "" {
		return nil, fmt.Errorf("service %q missing %s property", svc.Name, bom.PropToolsListSHA256)
	}
	pins, err := svc.ToolPins()
	if err != nil {
		return nil, fmt.Errorf("parse tool pins: %w", err)
	}
	allowedVal, _ := svc.GetProperty(bom.PropAllowedTools)
	stepUpVal, _ := svc.GetProperty(bom.PropStepUpTools)

	allowAll := strings.TrimSpace(allowedVal) == "*"
	var allowedSet map[string]struct{}
	if !allowAll {
		// Fail-closed least privilege: empty agbom:allowed_tools permits 0 tools.
		allowedSet = bom.ParseCSVProperty(allowedVal)
	}

	return &QuarantineProxy{
		serverName:      svc.Name,
		expectedHash:    expectedHash,
		expectedPins:    pins,
		allowAllTools:   allowAll,
		allowedTools:    allowedSet,
		stepUpTools:     bom.ParseCSVProperty(stepUpVal),
		upstreamTimeout: defaultUpstreamTimeout,
		logger:          logger,
		state:           StateUnverified,
		pinnedSchemas:   make(map[string]*CompiledSchema),
		pending:         make(map[string]chan rpcMsg),
		upClosed:        make(chan struct{}),
		quarantinedCh:   make(chan struct{}),
	}, nil
}

// SetNHIPrincipal configures the non-human identity principal attached to emitted ACS/OTLP events.
func (p *QuarantineProxy) SetNHIPrincipal(principal string) {
	p.stateMu.Lock()
	p.nhiPrincipal = principal
	p.stateMu.Unlock()
}

// SetApprovalHook attaches an optional external HITL step-up approval callback.
func (p *QuarantineProxy) SetApprovalHook(hook ApprovalHook) {
	p.stateMu.Lock()
	p.approvalHook = hook
	p.stateMu.Unlock()
}

// SetUpstreamTimeout overrides the per-call upstream RPC timeout (default 30s).
func (p *QuarantineProxy) SetUpstreamTimeout(d time.Duration) {
	p.stateMu.Lock()
	if d > 0 {
		p.upstreamTimeout = d
	}
	p.stateMu.Unlock()
}

// QuarantinedChan returns a channel that closes permanently as soon as the proxy enters QUARANTINED.
func (p *QuarantineProxy) QuarantinedChan() <-chan struct{} {
	return p.quarantinedCh
}

func (p *QuarantineProxy) getNHIPrincipal() string {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.nhiPrincipal
}

func (p *QuarantineProxy) getApprovalHook() ApprovalHook {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.approvalHook
}

func (p *QuarantineProxy) getUpstreamTimeout() time.Duration {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.upstreamTimeout
}

func (p *QuarantineProxy) State() State {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.state
}

// Serve runs the bidirectional JSON-RPC proxy loop until clientIn closes.
func (p *QuarantineProxy) Serve(clientIn io.Reader, clientOut io.Writer, upIn io.Writer, upOut io.Reader) error {
	p.clientWriteMu.Lock()
	p.clientWrite = clientOut
	p.clientWriteMu.Unlock()

	p.upstreamWriteMu.Lock()
	p.upstreamWrite = upIn
	p.upstreamWriteMu.Unlock()

	go func() {
		_ = p.readUpstreamLoop(upOut)
		p.upCloseOnce.Do(func() {
			close(p.upClosed)
		})
	}()

	scanner := bufio.NewScanner(clientIn)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if line[0] == '[' {
			p.replyError(json.RawMessage("null"), -32600, "invalid request: JSON-RPC batch arrays are not supported")
			continue
		}
		if _, err := canon.DecodeStrictJSON(line); err != nil {
			p.replyError(json.RawMessage("null"), -32700, "parse error: "+err.Error())
			continue
		}
		var msg rpcMsg
		if err := json.Unmarshal(line, &msg); err != nil {
			p.replyError(json.RawMessage("null"), -32700, "parse error: invalid JSON-RPC message")
			continue
		}
		p.handleClientMessage(msg)
	}
	return scanner.Err()
}

func (p *QuarantineProxy) readUpstreamLoop(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg rpcMsg
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}
		if len(msg.ID) == 0 || string(msg.ID) == "null" {
			if msg.Method == "notifications/tools/list_changed" {
				// CRITICAL: Intercept notification; silently re-verify before forwarding anything.
				go p.reverifyOnNotification()
				continue
			}
			if p.State() != StateQuarantined {
				p.writeClient(msg)
			}
			continue
		}

		idKey := canonicalIDKey(msg.ID)
		p.pendingMu.Lock()
		ch, ok := p.pending[idKey]
		if ok {
			delete(p.pending, idKey)
		}
		p.pendingMu.Unlock()
		if ok {
			ch <- msg
		}
	}
	return scanner.Err()
}

func canonicalIDKey(raw json.RawMessage) string {
	b, err := canon.JCS(raw)
	if err != nil {
		return strings.TrimSpace(string(raw))
	}
	return string(b)
}

func (p *QuarantineProxy) callUpstream(req rpcMsg) (rpcMsg, error) {
	origID := req.ID

	// Always assign a unique proxy-owned upstream request ID so client-chosen IDs
	// can never collide with internal verification requests or in-flight calls.
	p.pendingMu.Lock()
	p.upstreamIDSeq++
	upIDRaw, _ := json.Marshal(fmt.Sprintf("agbom-up-%d", p.upstreamIDSeq))
	req.ID = upIDRaw
	idKey := string(upIDRaw)
	ch := make(chan rpcMsg, 1)
	p.pending[idKey] = ch
	p.pendingMu.Unlock()

	if err := p.writeUpstream(req); err != nil {
		p.pendingMu.Lock()
		delete(p.pending, idKey)
		p.pendingMu.Unlock()
		return rpcMsg{}, err
	}

	timer := time.NewTimer(p.getUpstreamTimeout())
	defer timer.Stop()

	select {
	case resp := <-ch:
		resp.ID = origID
		return resp, nil
	case <-p.upClosed:
		p.pendingMu.Lock()
		delete(p.pending, idKey)
		p.pendingMu.Unlock()
		return rpcMsg{}, io.EOF
	case <-timer.C:
		p.pendingMu.Lock()
		delete(p.pending, idKey)
		p.pendingMu.Unlock()
		return rpcMsg{}, errors.New("upstream MCP request timed out")
	}
}

func (p *QuarantineProxy) handleClientMessage(msg rpcMsg) {
	if len(msg.ID) == 0 || string(msg.ID) == "null" {
		if p.State() != StateQuarantined {
			_ = p.writeUpstream(msg)
		}
		return
	}

	if p.State() == StateQuarantined {
		p.replyError(msg.ID, ErrCodeQuarantined, "MCP_SERVER_QUARANTINED_HASH_MISMATCH")
		return
	}

	switch msg.Method {
	case "initialize":
		resp, err := p.callUpstream(msg)
		if err != nil {
			p.replyError(msg.ID, -32603, err.Error())
			return
		}
		p.writeClient(resp)

	case "tools/list":
		filtered, err := p.verifyAndFilterTools()
		if err != nil {
			p.replyError(msg.ID, ErrCodeQuarantined, "MCP_SERVER_QUARANTINED_HASH_MISMATCH: "+err.Error())
			return
		}
		resBytes, _ := json.Marshal(map[string]any{"tools": filtered})
		p.writeClient(rpcMsg{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  resBytes,
		})

	case "tools/call":
		cleanParams, code, errMsg, ok := p.AuthorizeToolCall(context.Background(), msg.Params, "")
		if !ok {
			p.replyError(msg.ID, code, errMsg)
			return
		}
		msg.Params = cleanParams
		resp, err := p.callUpstream(msg)
		if err != nil {
			p.replyError(msg.ID, -32603, err.Error())
			return
		}
		p.writeClient(resp)

	default:
		resp, err := p.callUpstream(msg)
		if err != nil {
			p.replyError(msg.ID, -32603, err.Error())
			return
		}
		p.writeClient(resp)
	}
}

// AuthorizeToolCall enforces ACTIVE state, strict duplicate-key-free params decoding,
// fail-closed agbom:allowed_tools, pinned inputSchema argument validation, and
// agbom:step_up_approval_tools before returning canonicalized params safe to send upstream.
func (p *QuarantineProxy) AuthorizeToolCall(ctx context.Context, paramsRaw json.RawMessage, traceParent string) (sanitizedParams json.RawMessage, errCode int, errMsg string, ok bool) {
	state := p.State()
	if state == StateQuarantined {
		return nil, ErrCodeQuarantined, "MCP_SERVER_QUARANTINED_HASH_MISMATCH", false
	}
	if state != StateActive {
		return nil, ErrCodeToolBlocked, "MCP_SERVER_NOT_VERIFIED: run tools/list verification first", false
	}

	// Decode strictly to prevent duplicate-key parser differentials (e.g. {"name":"evil","name":"safe"}).
	if len(bytes.TrimSpace(paramsRaw)) == 0 {
		return nil, -32602, "invalid tools/call params: missing params object", false
	}
	if _, err := canon.DecodeStrictJSON(paramsRaw); err != nil {
		return nil, -32602, "invalid tools/call params: " + err.Error(), false
	}

	var callParams struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      json.RawMessage `json:"_meta,omitempty"`
	}
	if err := json.Unmarshal(paramsRaw, &callParams); err != nil || callParams.Name == "" {
		return nil, -32602, "invalid tools/call params", false
	}

	if !p.isToolAllowed(callParams.Name) {
		p.logger.Emit(telemetry.ACSEvent{
			EventType:    "agbom/tool_blocked",
			Severity:     "WARN",
			ServerName:   p.serverName,
			NHIPrincipal: p.getNHIPrincipal(),
			TraceParent:  traceParent,
			ToolName:     callParams.Name,
			Reason:       "tool not present in signed agbom:allowed_tools",
		})
		return nil, ErrCodeToolBlocked, fmt.Sprintf("TOOL_NOT_ALLOWED_BY_AGBOM: %s", callParams.Name), false
	}

	p.stateMu.Lock()
	schema := p.pinnedSchemas[callParams.Name]
	p.stateMu.Unlock()

	// Validate arguments strictly (including when schema == nil to reject duplicate keys in arguments).
	if err := schema.ValidateArguments(callParams.Arguments); err != nil {
		p.logger.Emit(telemetry.ACSEvent{
			EventType:    "agbom/tool_blocked",
			Severity:     "WARN",
			ServerName:   p.serverName,
			NHIPrincipal: p.getNHIPrincipal(),
			TraceParent:  traceParent,
			ToolName:     callParams.Name,
			Reason:       "pinned inputSchema validation failed: " + err.Error(),
		})
		return nil, ErrCodeInvalidArgs, fmt.Sprintf("TOOL_ARGS_SCHEMA_VIOLATION: %s: %v", callParams.Name, err), false
	}

	if _, requiresStepUp := p.stepUpTools[callParams.Name]; requiresStepUp {
		hook := p.getApprovalHook()
		if hook == nil {
			p.logger.Emit(telemetry.ACSEvent{
				EventType:    "agbom/tool_blocked",
				Severity:     "WARN",
				ServerName:   p.serverName,
				NHIPrincipal: p.getNHIPrincipal(),
				TraceParent:  traceParent,
				ToolName:     callParams.Name,
				Reason:       "step-up human approval required by AgBOM",
			})
			return nil, ErrCodeStepUpReq, fmt.Sprintf("STEP_UP_APPROVAL_REQUIRED: %s", callParams.Name), false
		}
		resp, err := hook(ctx, ApprovalRequest{
			ServerName:   p.serverName,
			ToolName:     callParams.Name,
			Arguments:    callParams.Arguments,
			NHIPrincipal: p.getNHIPrincipal(),
			TraceParent:  traceParent,
		})
		if err != nil || !resp.Approved {
			reason := "step-up approval denied by webhook"
			if err != nil {
				reason = "step-up approval webhook error (fail-closed): " + err.Error()
			} else if resp.Reason != "" {
				reason = "step-up approval denied: " + resp.Reason
			}
			p.logger.Emit(telemetry.ACSEvent{
				EventType:    "agbom/tool_blocked",
				Severity:     "WARN",
				ServerName:   p.serverName,
				NHIPrincipal: p.getNHIPrincipal(),
				TraceParent:  traceParent,
				ToolName:     callParams.Name,
				Reason:       reason,
			})
			return nil, ErrCodeStepUpReq, fmt.Sprintf("STEP_UP_APPROVAL_REQUIRED: %s (%s)", callParams.Name, reason), false
		}
		p.logger.Emit(telemetry.ACSEvent{
			EventType:    "agbom/step_up_approved",
			Severity:     "INFO",
			ServerName:   p.serverName,
			NHIPrincipal: p.getNHIPrincipal(),
			TraceParent:  traceParent,
			ToolName:     callParams.Name,
			Reason:       fmt.Sprintf("step-up approved by %s (%s)", resp.Approver, resp.Reason),
		})
	}

	// Re-serialize clean canonicalized params so upstream receives duplicate-key-free JSON.
	outObj := map[string]any{
		"name": callParams.Name,
	}
	trimmedArgs := bytes.TrimSpace(callParams.Arguments)
	if len(trimmedArgs) > 0 && !bytes.Equal(trimmedArgs, []byte("null")) {
		canonArgs, err := canon.JCS(trimmedArgs)
		if err != nil {
			return nil, -32602, "canonicalize arguments: " + err.Error(), false
		}
		outObj["arguments"] = json.RawMessage(canonArgs)
	}
	if len(bytes.TrimSpace(callParams.Meta)) > 0 {
		canonMeta, err := canon.JCS(callParams.Meta)
		if err != nil {
			return nil, -32602, "canonicalize _meta: " + err.Error(), false
		}
		outObj["_meta"] = json.RawMessage(canonMeta)
	}
	cleanBytes, err := json.Marshal(outObj)
	if err != nil {
		return nil, -32603, err.Error(), false
	}

	return cleanBytes, 0, "", true
}

func (p *QuarantineProxy) isToolAllowed(name string) bool {
	if p.allowAllTools {
		return true
	}
	_, ok := p.allowedTools[name]
	return ok
}

func (p *QuarantineProxy) verifyAndFilterTools() ([]json.RawMessage, error) {
	return p.VerifyWithFetcher("", func() ([]json.RawMessage, error) {
		var allTools []json.RawMessage
		var cursor string
		completed := false
		for page := 0; page < MaxPages; page++ {
			paramsBytes := []byte("{}")
			if cursor != "" {
				paramsBytes, _ = json.Marshal(map[string]any{"cursor": cursor})
			}
			resp, err := p.callUpstream(rpcMsg{
				JSONRPC: "2.0",
				Method:  "tools/list",
				Params:  paramsBytes,
			})
			if err != nil {
				return nil, fmt.Errorf("upstream tools/list error: %w", err)
			}
			if resp.Error != nil {
				return nil, errors.New(resp.Error.Message)
			}
			var listRes struct {
				Tools      []json.RawMessage `json:"tools"`
				NextCursor string            `json:"nextCursor"`
			}
			if err := json.Unmarshal(resp.Result, &listRes); err != nil {
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

// VerifyWithFetcher executes the fail-closed VERIFYING -> ACTIVE / QUARANTINED transition
// using any transport-specific tool fetcher (stdio or Streamable HTTP).
func (p *QuarantineProxy) VerifyWithFetcher(traceParent string, fetch func() ([]json.RawMessage, error)) ([]json.RawMessage, error) {
	p.verifyMu.Lock()
	defer p.verifyMu.Unlock()

	p.stateMu.Lock()
	if p.state == StateQuarantined {
		p.stateMu.Unlock()
		return nil, errors.New("server already quarantined")
	}
	p.state = StateVerifying
	p.stateMu.Unlock()

	allTools, err := fetch()
	if err != nil {
		p.quarantine("", nil, "", err.Error(), traceParent)
		return nil, err
	}

	compHash, pins, err := canon.HashToolSet(allTools)
	if err != nil {
		p.quarantine("", nil, "", err.Error(), traceParent)
		return nil, err
	}
	if compHash != p.expectedHash {
		drifted := canon.DiffPins(p.expectedPins, pins)
		redactedDiff := buildRedactedDriftSummary(allTools, drifted)
		p.quarantine(compHash, drifted, redactedDiff, "tools_list_sha256 mismatch against signed AgBOM", traceParent)
		return nil, fmt.Errorf("expected %s, got %s (drifted: %v)", p.expectedHash, compHash, drifted)
	}

	compiledSchemas := make(map[string]*CompiledSchema, len(allTools))
	for _, raw := range allTools {
		var toolMeta struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"inputSchema"`
		}
		if err := json.Unmarshal(raw, &toolMeta); err == nil && toolMeta.Name != "" && len(toolMeta.InputSchema) > 0 {
			cs, err := CompileInputSchema(toolMeta.InputSchema)
			if err != nil {
				p.quarantine(compHash, []string{toolMeta.Name}, "", "invalid pinned inputSchema: "+err.Error(), traceParent)
				return nil, fmt.Errorf("compile pinned inputSchema for %s: %w", toolMeta.Name, err)
			}
			compiledSchemas[toolMeta.Name] = cs
		}
	}

	p.stateMu.Lock()
	if p.state == StateQuarantined {
		p.stateMu.Unlock()
		return nil, errors.New("server already quarantined")
	}
	p.pinnedSchemas = compiledSchemas
	p.state = StateActive
	p.stateMu.Unlock()

	p.logger.Emit(telemetry.ACSEvent{
		EventType:    "agbom/snapshot",
		Severity:     "INFO",
		ServerName:   p.serverName,
		NHIPrincipal: p.getNHIPrincipal(),
		TraceParent:  traceParent,
		ExpectedHash: p.expectedHash,
		ObservedHash: compHash,
		Reason:       "tools/list verified against signed AgBOM",
	})

	if p.allowAllTools {
		return allTools, nil
	}
	// Fail-closed: if allowedTools is empty, 0 tools are exposed to the client.
	filtered := make([]json.RawMessage, 0, len(allTools))
	for _, raw := range allTools {
		var env struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &env) == nil {
			if _, ok := p.allowedTools[env.Name]; ok {
				filtered = append(filtered, raw)
			}
		}
	}
	return filtered, nil
}

func (p *QuarantineProxy) reverifyOnNotification() {
	if _, err := p.verifyAndFilterTools(); err == nil {
		p.writeClient(rpcMsg{
			JSONRPC: "2.0",
			Method:  "notifications/tools/list_changed",
		})
	}
}

func (p *QuarantineProxy) quarantine(observedHash string, drifted []string, redactedDiff, reason, traceParent string) {
	p.stateMu.Lock()
	p.state = StateQuarantined
	nhi := p.nhiPrincipal
	p.stateMu.Unlock()

	p.quarantineOnce.Do(func() {
		close(p.quarantinedCh)
	})

	p.logger.Emit(telemetry.ACSEvent{
		EventType:    "agbom/quarantined",
		Severity:     "CRITICAL",
		ServerName:   p.serverName,
		NHIPrincipal: nhi,
		TraceParent:  traceParent,
		ExpectedHash: p.expectedHash,
		ObservedHash: observedHash,
		DriftedTools: drifted,
		RedactedDiff: redactedDiff,
		Reason:       reason,
	})
}

func (p *QuarantineProxy) replyError(id json.RawMessage, code int, msg string) {
	p.writeClient(rpcMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcErr{Code: code, Message: msg},
	})
}

func (p *QuarantineProxy) writeClient(msg rpcMsg) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	p.clientWriteMu.Lock()
	defer p.clientWriteMu.Unlock()
	_, _ = p.clientWrite.Write(append(b, '\n'))
}

func (p *QuarantineProxy) writeUpstream(msg rpcMsg) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	p.upstreamWriteMu.Lock()
	defer p.upstreamWriteMu.Unlock()
	_, err = p.upstreamWrite.Write(append(b, '\n'))
	return err
}
