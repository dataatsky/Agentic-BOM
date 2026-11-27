package mcpclient

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

const MaxPaginationPages = 50

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// FetchToolsStdio launches a stdio MCP server, completes initialize, and retrieves
// all pages of tools/list as raw JSON tool objects.
func FetchToolsStdio(command string, args []string) ([]json.RawMessage, error) {
	cmd := exec.Command(command, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start mcp server: %w", err)
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	return FetchToolsOverPipes(stdin, stdout)
}

// FetchToolsOverPipes performs initialize + paginated tools/list over arbitrary streams.
func FetchToolsOverPipes(w io.Writer, r io.Reader) ([]json.RawMessage, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	send := func(req rpcRequest) (*rpcResponse, error) {
		b, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return nil, err
		}
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var resp rpcResponse
			if err := json.Unmarshal(line, &resp); err != nil {
				continue
			}
			// Ignore server notifications while waiting for response.
			if len(resp.ID) == 0 || string(resp.ID) == "null" {
				continue
			}
			if resp.Error != nil {
				return nil, fmt.Errorf("mcp rpc error %d: %s", resp.Error.Code, resp.Error.Message)
			}
			return &resp, nil
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}

	// 1. initialize
	if _, err := send(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": "2026-07-28",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "agbom-gate-scanner", "version": "0.1.0"},
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
		resp, err := send(rpcRequest{
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
