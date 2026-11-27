package mcpclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestFetchToolsHTTPPaginatedAndSSE(t *testing.T) {
	var seenAuth []string
	var seenSession string

	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seenAuth = append(seenAuth, r.Header.Get("Authorization"))
			body, _ := io.ReadAll(r.Body)
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params map[string]any  `json:"params"`
			}
			_ = json.Unmarshal(body, &req)

			hdr := make(http.Header)
			switch req.Method {
			case "initialize":
				hdr.Set("Content-Type", "application/json")
				hdr.Set("Mcp-Session-Id", "sess-42")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     hdr,
					Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28"}}`)),
				}, nil
			case "tools/list":
				seenSession = r.Header.Get("Mcp-Session-Id")
				if cursor, _ := req.Params["cursor"].(string); cursor == "" {
					// Page 1 returned as SSE text/event-stream
					hdr.Set("Content-Type", "text/event-stream")
					sse := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"tool_a\"}],\"nextCursor\":\"p2\"}}\n\n"
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     hdr,
						Body:       io.NopCloser(strings.NewReader(sse)),
					}, nil
				}
				// Page 2 returned as application/json
				hdr.Set("Content-Type", "application/json")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     hdr,
					Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"tool_b"}]}}`)),
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	}

	tools, err := FetchToolsHTTP(context.Background(), HTTPConfig{
		EndpointURL: "https://mcp.corp.internal/mcp",
		OBOToken:    "obo-secret-123",
		HTTPClient:  client,
	})
	if err != nil {
		t.Fatalf("FetchToolsHTTP: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools across 2 pages, got %d", len(tools))
	}
	if seenSession != "sess-42" {
		t.Fatalf("expected Mcp-Session-Id sess-42 propagated, got %q", seenSession)
	}
	for _, a := range seenAuth {
		if a != "Bearer obo-secret-123" {
			t.Fatalf("expected OBO bearer token on all requests, got %q", a)
		}
	}
}

func TestSplitCommandArgsQuotesAndEscapes(t *testing.T) {
	got, err := SplitCommandArgs(`--mode=clean --config "/path/with spaces/mcp.json" '--tag=a b' escaped\ arg`)
	if err != nil {
		t.Fatalf("SplitCommandArgs: %v", err)
	}
	want := []string{"--mode=clean", "--config", "/path/with spaces/mcp.json", "--tag=a b", "escaped arg"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg[%d]: got %q, want %q", i, got[i], want[i])
		}
	}

	if _, err := SplitCommandArgs(`--config "unterminated`); err == nil {
		t.Fatal("expected error on unterminated quote")
	}
}
