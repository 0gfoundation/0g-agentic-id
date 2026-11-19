package servicehost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"seal-verify/internal/servicenet"
)

// The network adapters (servicenet) against sealed's own egress proxy: each
// fixture runs its runtime's ordinary clients and prints one line per check.
// With MCP_SOCKET set it answers each request with those lines instead.

const nodeNetFixture = `import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import tls from 'node:tls'
const { host, http: P1, https: P2, echo: P3 } = JSON.parse(process.env.NET_TEST)
async function checks() {
  const out = []
  const check = async (name, fn, want) => {
    let got
    try { got = String(await fn()) } catch (e) { got = 'threw ' + (e && e.message) + (e && e.cause ? ' cause: ' + e.cause.message : '') }
    out.push(got.includes(want) ? 'ok ' + name : 'FAIL ' + name + ': ' + got.slice(0, 200))
  }
  const body = res => new Promise((resolve, reject) => { let b = ''; res.setEncoding('utf8'); res.on('data', c => { b += c }); res.on('end', () => resolve(b)); res.on('error', reject) })
  const get = (mod, url) => new Promise((resolve, reject) => mod.get(url, res => body(res).then(resolve, reject)).on('error', reject))
  await check('fetch http', async () => (await fetch('http://' + host + ':' + P1 + '/a')).text(), 'target GET /a')
  await check('fetch https', async () => (await fetch('https://' + host + ':' + P2 + '/b', { method: 'POST', body: 'x'.repeat(70000) })).text(), 'target POST /b 70000')
  await check('http.get', () => get(http, 'http://' + host + ':' + P1 + '/c'), 'target GET /c')
  await check('https.get', () => get(https, 'https://' + host + ':' + P2 + '/d'), 'target GET /d')
  await check('net.connect', () => new Promise((resolve, reject) => {
    const s = net.connect({ host, port: P3 }); s.write('ping')
    s.once('data', c => { s.destroy(); resolve(c) }); s.on('error', reject)
  }), 'ping')
  await check('tls.connect', () => new Promise((resolve, reject) => {
    const s = tls.connect({ host, port: P2, servername: host }, () => s.write('GET /t HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n'))
    let b = ''; s.on('data', c => { b += c }); s.on('end', () => resolve(b)); s.on('error', reject)
  }), 'target GET /t')
  await check('refused', () => fetch('https://denied.example/'), 'Egress proxy refused denied.example:443 (HTTP 403)')
  if (process.env.SEAL_MODEL_URL) await check('model', async () => (await fetch(process.env.SEAL_MODEL_URL + '/chat/completions', { method: 'POST', body: '{}' })).text(), 'model POST /model/chat/completions')
  return out.join('\n')
}
if (process.env.MCP_SOCKET) http.createServer(async (req, res) => { req.resume(); res.end(await checks()) }).listen(process.env.MCP_SOCKET)
else console.log(await checks())
`

const pythonNetFixture = `import asyncio, http.client, http.server, json, os, socket, ssl, sys, urllib.request
t = json.loads(os.environ["NET_TEST"])
host, P1, P2, P3 = t["host"], t["http"], t["https"], t["echo"]
def checks():
    out = []
    def check(name, fn, want):
        try:
            got = str(fn())
        except Exception as e:
            got = "threw %s: %s" % (type(e).__name__, e)
        out.append("ok " + name if want in got else "FAIL %s: %s" % (name, got[:200]))
    get = lambda url: urllib.request.urlopen(url, timeout=10).read().decode()
    check("urllib http", lambda: get("http://%s:%d/a" % (host, P1)), "target GET /a")
    check("urllib https", lambda: get("https://%s:%d/b" % (host, P2)), "target GET /b")
    def client():
        c = http.client.HTTPSConnection(host, P2, timeout=10)
        c.request("POST", "/c", body=b"x" * 70000)
        return c.getresponse().read().decode()
    check("http.client", client, "target POST /c 70000")
    def echo():
        s = socket.create_connection((host, P3), timeout=10)
        s.sendall(b"ping")
        r = s.recv(4)
        s.close()
        return r.decode()
    check("create_connection", echo, "ping")
    async def stream():
        r, w = await asyncio.open_connection(host, P2, ssl=ssl.create_default_context())
        w.write(("GET /t HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
        data = await r.read()
        w.close()
        return data.decode()
    check("asyncio", lambda: asyncio.run(stream()), "target GET /t")
    check("refused", lambda: get("https://denied.example/"), "Egress proxy refused denied.example:443 (HTTP 403)")
    if os.environ.get("SEAL_MODEL_URL"):
        req = urllib.request.Request(os.environ["SEAL_MODEL_URL"] + "/chat/completions", data=b"{}")
        check("model", lambda: urllib.request.urlopen(req, timeout=10).read().decode(), "model POST /model/chat/completions")
    return "\n".join(out)
if not os.environ.get("MCP_SOCKET"):
    print(checks())
    sys.exit(0)
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        b = checks().encode()
        self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
class Server(http.server.HTTPServer):
    address_family = socket.AF_UNIX
    def server_bind(self): self.socket.bind(self.server_address); self.server_name = "task"; self.server_port = 0
Server(os.environ["MCP_SOCKET"], Handler).serve_forever()
`

// netFixtures: what each runtime's fixture checks, without the model check.
var netFixtures = []struct {
	name, command, file, source string
	checks                      int
}{
	{"node", "node", "net.mjs", nodeNetFixture, 7},
	{"python", "python3", "net.py", pythonNetFixture, 6},
}

type netTargets struct {
	host     string
	ports    map[string]int // http, https, echo
	egress   []string
	dial     func(context.Context, string, string) (net.Conn, error)
	certPEM  []byte
	settings string // NET_TEST
}

// startNetTargets starts an HTTP, an HTTPS and a TCP echo server on loopback,
// reachable through the egress proxy as example.com (the name in httptest's
// certificate) at their own ports.
func startNetTargets(t *testing.T) *netTargets {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "target %s %s %d", r.Method, r.URL.Path, n)
	})
	plain := httptest.NewServer(handler)
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(handler)
	t.Cleanup(secure.Close)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	tg := &netTargets{host: "example.com", ports: map[string]int{}}
	upstream := map[string]string{}
	for name, addr := range map[string]string{"http": plain.Listener.Addr().String(), "https": secure.Listener.Addr().String(), "echo": echo.Addr().String()} {
		_, port, _ := net.SplitHostPort(addr)
		hostPort := net.JoinHostPort(tg.host, port)
		tg.ports[name], _ = strconv.Atoi(port)
		tg.egress = append(tg.egress, hostPort)
		upstream[hostPort] = addr
	}
	tg.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		to, ok := upstream[addr]
		if !ok {
			return nil, fmt.Errorf("unexpected destination %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, to)
	}
	tg.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw})
	b, _ := json.Marshal(map[string]any{"host": tg.host, "http": tg.ports["http"], "https": tg.ports["https"], "echo": tg.ports["echo"]})
	tg.settings = string(b)
	return tg
}

func checkNetOutput(t *testing.T, out string, want int) {
	t.Helper()
	ok := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, "ok ") {
			ok++
		} else {
			t.Errorf("%s", line)
		}
	}
	if ok != want {
		t.Fatalf("%d of %d checks passed:\n%s", ok, want, out)
	}
}

// The adapters route ordinary clients through sealed's real egress proxy
// (and a stand-in model socket); this needs only the interpreters.
func TestNetworkAdaptersRouteThroughSealedProxies(t *testing.T) {
	tg := startNetTargets(t)
	dir := t.TempDir()
	adapters := filepath.Join(dir, "net")
	if err := servicenet.Install(adapters); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{egressDial: tg.dial}
	egress := filepath.Join(dir, "egress.sock")
	if err := m.startEgress(ctx, tg.egress, uint32(os.Getuid()), egress); err != nil {
		t.Fatal(err)
	}
	model := filepath.Join(dir, "model.sock")
	ml, err := net.Listen("unix", model)
	if err != nil {
		t.Fatal(err)
	}
	modelServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "model %s %s", r.Method, r.URL.Path)
	})}
	go func() { _ = modelServer.Serve(ml) }()
	defer modelServer.Close()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, tg.certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	for _, f := range netFixtures {
		t.Run(f.name, func(t *testing.T) {
			bin, err := exec.LookPath(f.command)
			if err != nil {
				t.Skipf("no %s here", f.command)
			}
			script := filepath.Join(dir, f.file)
			if err := os.WriteFile(script, []byte(f.source), 0644); err != nil {
				t.Fatal(err)
			}
			args := []string{script}
			if f.name == "node" {
				args = []string{"--import", servicenet.NodeBootstrap(adapters), script}
			}
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir = dir
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "NET_TEST=" + tg.settings,
				"SEAL_EGRESS_SOCKET=" + egress, "SEAL_MODEL_SOCKET=" + model,
				"NODE_EXTRA_CA_CERTS=" + cert, "SSL_CERT_FILE=" + cert, "PYTHONPATH=" + servicenet.PythonPath(adapters)}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			checkNetOutput(t, string(out), f.checks+1)
		})
	}
}

// Confined service processes load the adapters from sealed: Landlock lets
// them read the adapters, and their clients reach the egress allowlist.
func TestConfinedServicesUseNetworkAdapters(t *testing.T) {
	root(t)
	if os.Getenv("SEALED_SERVICE_TESTS") != "1" {
		t.Skip("set SEALED_SERVICE_TESTS=1 as root on a kernel with Landlock ABI 6")
	}
	tg := startNetTargets(t)
	m, err := NewWithOptions(filepath.Join(t.TempDir(), "services"), "owner:identity", Options{SkipResourceLimitsForTests: true, EgressDial: tg.dial})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ran := 0
	for _, f := range netFixtures {
		t.Run(f.name, func(t *testing.T) {
			if _, err := exec.LookPath(f.command); err != nil {
				t.Skipf("no %s here", f.command)
			}
			ran++
			man := Manifest{ID: "net-" + f.name, Command: f.command, Args: []string{f.file},
				Files: []File{{Path: f.file, Data: base64.StdEncoding.EncodeToString([]byte(f.source))},
					{Path: "cert.pem", Data: base64.StdEncoding.EncodeToString(tg.certPEM)}},
				Network: "egress", EgressHosts: tg.egress,
				Env: map[string]string{"NET_TEST": tg.settings, "NODE_EXTRA_CA_CERTS": "cert.pem", "SSL_CERT_FILE": "cert.pem"}}
			if _, err := m.Publish(man); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Start(man.ID); err != nil {
				t.Fatal(err)
			}
			resp, err := m.HTTPClient(man.ID).Do(taskRequest(context.Background(), f.name, 0, testServiceVersion(m, man.ID)))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("request: %d %s", resp.StatusCode, b)
			}
			checkNetOutput(t, string(b), f.checks)
		})
	}
	if ran == 0 {
		t.Fatal("neither node nor python3 is installed")
	}
}

func TestInterpreterRuntimeNamesTheAdapter(t *testing.T) {
	for path, want := range map[string]interpreterKind{
		"/usr/local/bin/node": nodeRuntime, "/usr/bin/python3": pythonRuntime, "/usr/bin/python3.13": pythonRuntime,
		"/usr/bin/python": pythonRuntime, "/usr/bin/bash": otherRuntime, "/usr/bin/python3-config": otherRuntime, "/usr/bin/nodejs": otherRuntime,
	} {
		if got := interpreterRuntime(path); got != want {
			t.Errorf("%s: got %d, want %d", path, got, want)
		}
	}
}
