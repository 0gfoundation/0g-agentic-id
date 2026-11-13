package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"seal-verify/internal/inferproxy"
	"seal-verify/internal/servicehost"
)

func TestRuntimeInputCannotReachSharedBackend(t *testing.T) {
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))
	defer backend.Close()
	s, _ := armedProxy(t, backend.URL, testValidator)
	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(`{}`))
	req.Header.Set(servicehost.RuntimeInputHeader, base64.StdEncoding.EncodeToString([]byte(`{"token":"fixture"}`)))
	out := httptest.NewRecorder()
	s.handleProxy(out, req)
	if out.Code != 400 || called {
		t.Fatal("runtime input escaped into a shared backend")
	}
}

// This opt-in test crosses the public proxy, the real sandbox/UID launcher,
// the image-bundled Node/DSH composition and an actual native tool execution.
// /opt/0g-harness/base and the package it names must be mounted read-only by
// the integration test container; no live model, chain or credentials are used.
func TestPublicMCPTemporaryDSHLoop(t *testing.T) {
	if os.Getenv("SEALED_LOOP_TESTS") != "1" {
		t.Skip("requires Linux root, Node and the companion Harness package")
	}
	if os.Geteuid() != 0 {
		t.Fatal("loop integration requires root")
	}
	var mu sync.Mutex
	var requests []string
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sealed-model-fixture" {
			t.Error("worker escaped pinned inference key")
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, string(b))
		mu.Unlock()
		var req struct {
			Messages []struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(b, &req); err != nil {
			t.Error(err)
		}
		afterTool := false
		for _, m := range req.Messages {
			if m.Role == "tool" {
				afterTool = true
				if !strings.Contains(string(m.Content), "true") {
					t.Error("native tool did not receive task input")
				}
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if afterTool {
			fmt.Fprint(w, "data: {\"id\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"access confirmed\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
		} else {
			fmt.Fprint(w, "data: {\"id\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"check_access\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}\n\ndata: {\"id\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer model.Close()
	base, err := os.ReadFile("/opt/0g-harness/base")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("/opt/0g-harness", strings.TrimSpace(string(base)))
	server, err := os.ReadFile(filepath.Join(root, "skills/publish-mcp-service/loop-server.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`
import {pathToFileURL} from 'node:url'
const {mountServiceModel,defineTool}=await import(pathToFileURL(process.env.HARNESS_RUNTIME_ROOT+'/src/service-loop.mjs'))
const model={provider:'loop-mock',id:'mock',baseURL:%q}
export default {model,persona:'Use check_access to perform the task.',cwd:'/work',
 async configure(ctx,{runtimeInput}) {
  await mountServiceModel(ctx,model)
  ctx.tools.register(defineTool({name:'check_access',description:'Check access without disclosing credentials',parameters:{},
   output:{schema:{type:'boolean'},render:(_,v)=>[{type:'text',text:String(v)}]},execute:async()=>Boolean(runtimeInput.token)}))
 }}
`, model.URL+"/v1")
	host, err := servicehost.NewWithOptions(filepath.Join(t.TempDir(), "services"), "owner:identity", servicehost.Options{AcquireRuntime: func(context.Context) (servicehost.RuntimeLease, error) {
		return servicehost.RuntimeLease{Hash: strings.TrimSpace(string(base)), Dir: root, Release: func() {}}, nil
	}, ModelRoute: func(context.Context) (servicehost.ModelRoute, error) {
		return servicehost.ModelRoute{API: "openai-completions", Route: inferproxy.Route{Upstream: model.URL + "/v1", Model: "mock", Headers: map[string]string{"Authorization": "Bearer sealed-model-fixture"}}}, nil
	}, EgressDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, model.Listener.Addr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if _, err := host.Publish(servicehost.Manifest{ID: "loop", Command: "node", Args: []string{"/app/loop-server.mjs"}, Network: "none", InferenceBudget: &inferproxy.TaskLimits{Calls: 2, InputBytes: 65536, OutputTokens: 512}, RequestTimeoutSeconds: 15,
		Files: []servicehost.File{{Path: "loop-server.mjs", Data: base64.StdEncoding.EncodeToString(server)}, {Path: "agent-config.mjs", Data: base64.StdEncoding.EncodeToString([]byte(config))}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Start("loop"); err != nil {
		t.Fatal(err)
	}
	s, _ := armedProxy(t, "http://localhost", testValidator)
	s.strictServices = true // This fixture selects the hosting adapter without bootstrapping it.
	s.SetServiceHost(host)
	front := httptest.NewServer(http.HandlerFunc(s.handleProxy))
	defer front.Close()
	input, _ := json.Marshal(map[string]string{"token": "employer-integration-fixture"})
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":{"prompt":"check my access"}}}`,
	} {
		req, _ := http.NewRequest("POST", front.URL+"/api/mcp/loop", strings.NewReader(body))
		req.Header.Set(servicehost.RuntimeInputHeader, base64.StdEncoding.EncodeToString(input))
		req.Header.Set(servicehost.ServiceVersionHeader, host.List()[0].Version)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("public loop: %d %s", resp.StatusCode, out)
		}
		if strings.Contains(body, "tools/call") && !strings.Contains(string(out), "access confirmed") {
			t.Fatalf("loop result: %s", out)
		}
		if resp.Header.Get("X-Agent-Proof") == "" {
			t.Fatal("finite task result lost attribution")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("expected actual tool round trip, got %d model calls", len(requests))
	}
	for _, b := range requests {
		if strings.Contains(b, "employer-integration-fixture") {
			t.Fatal("private input leaked into model context")
		}
	}
}
