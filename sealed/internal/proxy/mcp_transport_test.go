package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMCPMethodsSessionHeadersAndLiveSSE(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Mcp-Session-Id") != "tenant-session" || r.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
			t.Error("session/protocol header lost")
		}
		w.Header().Set("Mcp-Session-Id", "tenant-session")
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Agent-Proof", "forged")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"sampling/createMessage\"}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer backend.Close()
	s, _ := armedProxy(t, backend.URL, "")
	s.services = []ServiceEntry{{Path: "/api/test-mcp", Method: "POST", Backend: backend.URL, Transport: "mcp"}}
	front := httptest.NewServer(http.HandlerFunc(s.handleProxy))
	defer front.Close()
	for _, method := range []string{"POST", "GET"} {
		req, _ := http.NewRequest(method, front.URL+"/api/test-mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
		req.Header.Set("Mcp-Session-Id", "tenant-session")
		req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("stream was buffered:", err)
		}
		if resp.Header.Get("X-Agent-Proof") != "" || resp.Header.Get("X-Agent-Proof-Mode") != "stream-unsigned" {
			t.Fatal("false stream attribution")
		}
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		resp.Body.Close()
		if err != nil || !strings.Contains(line, "sampling/createMessage") {
			t.Fatalf("server request not relayed: %q %v", line, err)
		}
	}
	close(release)
	req, _ := http.NewRequest("DELETE", front.URL+"/api/test-mcp", nil)
	req.Header.Set("Mcp-Session-Id", "tenant-session")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("DELETE: %d", resp.StatusCode)
	}
}
