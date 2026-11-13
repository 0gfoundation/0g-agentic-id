package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/servicehost"
)

// Runs both companion PRs together: the official MCP/x402 clients, real wallet
// signatures, a namespace-isolated coordinator and worker, and sealed's receipt
// verifier. The facilitator/RPC simulate a chain; no money or live APIs are used.
func TestPublicPaidMCPWithExecutionReceipt(t *testing.T) {
	if os.Getenv("SEALED_LOOP_TESTS") != "1" {
		t.Skip("requires Linux root, Node and the companion Harness package")
	}
	b, err := os.ReadFile("/opt/0g-harness/base")
	if err != nil {
		t.Fatal(err)
	}
	runtimeHash := strings.TrimSpace(string(b))
	runtime := filepath.Join("/opt/0g-harness", runtimeHash)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", filepath.Join(runtime, "test/helpers/paid-stack.mjs"))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("payment fixture startup: %s", stderr.String())
	}
	var fixture struct{ Address, Asset, PayTo, Network string }
	if err := json.Unmarshal(scanner.Bytes(), &fixture); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "services")
	host, err := servicehost.NewWithOptions(stateDir, "owner:identity", servicehost.Options{AcquireRuntime: func(context.Context) (servicehost.RuntimeLease, error) {
		return servicehost.RuntimeLease{Hash: runtimeHash, Dir: runtime, Release: func() {}}, nil
	}, EgressDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, fixture.Address)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	s, signer := armedProxy(t, "http://localhost", testValidator)
	s.strictServices = true // This fixture selects the hosting adapter without bootstrapping it.
	s.SetServiceHost(host)
	front := httptest.NewServer(http.HandlerFunc(s.handleProxy))
	defer front.Close()
	url := front.URL + "/api/mcp/paid"
	config := fmt.Sprintf(`import {pathToFileURL} from 'node:url'
const {z}=await import(pathToFileURL(process.env.HARNESS_RUNTIME_ROOT+'/src/service-paid.mjs'))
export default {id:'paid',publicUrl:%q,pollMs:20,settlementRetryMs:1000,inputSchema:z.object({text:z.string().max(1000),delay_ms:z.number().int().min(0).max(3000)}).strict(),
 payment:{network:%q,payTo:%q,price:{amount:'1',asset:%q,extra:{name:'Fixture USD',version:'2'}},facilitatorUrl:'http://facilitator.example',rpcUrl:'http://rpc.example/rpc'}}
`, url, fixture.Network, fixture.PayTo, fixture.Asset)
	worker := `import {setTimeout as delay} from 'node:timers/promises'
export default async function(input,{runtimeInput,progress}) {
 progress({phase:'working',steps:1});await delay(input.delay_ms)
 return {text:input.text,authorized:runtimeInput.token==='private-joint-fixture'}
}`
	files := []servicehost.File{}
	for _, name := range []string{"paid-server.mjs", "paid-worker.mjs"} {
		data, err := os.ReadFile(filepath.Join(runtime, "skills/publish-mcp-service", name))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, servicehost.File{Path: name, Data: base64.StdEncoding.EncodeToString(data)})
	}
	for name, data := range map[string]string{"service-config.mjs": config, "worker-config.mjs": worker} {
		files = append(files, servicehost.File{Path: name, Data: base64.StdEncoding.EncodeToString([]byte(data))})
	}
	status, err := host.Publish(servicehost.Manifest{ID: "paid", Command: "node", Args: []string{"/app/paid-server.mjs"}, Worker: &servicehost.Program{Command: "node", Args: []string{"/app/paid-worker.mjs"}}, Files: files, Network: "egress", EgressHosts: []string{"facilitator.example:80", "rpc.example:80"}, RequestTimeoutSeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.Start("paid"); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(15 * time.Second); ; {
		if host.List()[0].State == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("coordinator not ready: %+v", host.List())
		}
		time.Sleep(25 * time.Millisecond)
	}
	clientConfig := map[string]any{"url": url, "version": status.Version, "trust": map[string]any{"signer": signer.Hex(), "validator": testValidator, "chainId": "16602", "identityRegistry": "0x00000000000000000000000000000000000000A9", "agentId": "30", "workerRuntimeHash": runtimeHash}}
	if err := json.NewEncoder(stdin).Encode(clientConfig); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	var output strings.Builder
	for scanner.Scan() {
		output.Write(scanner.Bytes())
		output.WriteByte('\n')
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("paid MCP client: %v\n%s\n%s", err, output.String(), stderr.String())
	}
	if !strings.Contains(output.String(), `"ok":true`) {
		t.Fatalf("missing end-to-end result: %s\n%s", output.String(), stderr.String())
	}
	// Business input, payments and results belong to the isolated application's
	// private work. Sealed's own process registry contains only hashes/metadata.
	entries, err := os.ReadDir(filepath.Join(stateDir, "executions"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected one paid, one cancelled and one recovered-payment worker, got %d", len(entries))
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(stateDir, "executions", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "private-joint-fixture") || strings.Contains(string(data), "paid isolated fixture") {
			t.Fatal("business input persisted in sealed process registry")
		}
	}
}
