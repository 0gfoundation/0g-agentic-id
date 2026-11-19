package servicehost

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentDataGrantIsPartOfTheRelease(t *testing.T) {
	plain := manifest("demo", "x")
	v0, err := plain.normalize()
	if err != nil {
		t.Fatal(err)
	}
	empty := manifest("demo", "x")
	empty.AgentData = &AgentDataGrant{}
	if _, err := empty.normalize(); err == nil {
		t.Fatal("an agent_data grant naming nothing accepted")
	}
	granted := manifest("demo", "x")
	granted.AgentData = &AgentDataGrant{Persona: true, PublicMemory: true}
	v1, err := granted.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if v0 == v1 {
		t.Fatal("the grant does not change the audited release version")
	}
	if got := granted.AgentData.Kinds(); strings.Join(got, ",") != "persona,public_memory" {
		t.Fatalf("kinds %v", got)
	}
	// A release without the field keeps its version (omitempty).
	again := manifest("demo", "x")
	if v, _ := again.normalize(); v != v0 {
		t.Fatal("a release without agent_data changed version")
	}
}

func TestAgentDataListingHash(t *testing.T) {
	a := AgentDataListingHash(map[string][]byte{"b.md": []byte("2"), "a.md": []byte("1")})
	b := AgentDataListingHash(map[string][]byte{"a.md": []byte("1"), "b.md": []byte("2")})
	if a != b || a == AgentDataListingHash(map[string][]byte{"a.md": []byte("1")}) || a == AgentDataListingHash(map[string][]byte{"a.md": []byte("1"), "b.md": []byte("3")}) {
		t.Fatal("listing hash not deterministic or not content-bound")
	}
}

// The job's copy is read-only, root-owned, and independent of its source:
// a later commit (a new version directory, or even a change in place) never
// changes what a running job reads.
func TestStageAgentDataIsAReadOnlyCopy(t *testing.T) {
	root(t)
	src := t.TempDir()
	persona := filepath.Join(src, "persona")
	skills := filepath.Join(src, "skills")
	for _, d := range []string{persona, filepath.Join(skills, "brief")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(persona, "APPEND_SYSTEM.md"), "be brief")
	write(filepath.Join(skills, "brief", "SKILL.md"), "# brief")
	parts := []AgentDataPart{
		{Dir: persona, Version: AgentDataVersion{Kind: AgentDataPersona, ContentHash: "c1", DataHash: "0xd1", SnapshotHash: "s1", Files: 1}},
		{Dir: skills, Version: AgentDataVersion{Kind: AgentDataSkills, ContentHash: "c2", DataHash: "0xd2", SnapshotHash: "s2", Files: 1}},
	}
	dst := filepath.Join(t.TempDir(), "agent-data")
	versions, err := stageAgentData(dst, parts)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[1].Kind != AgentDataSkills {
		t.Fatalf("versions %+v", versions)
	}
	for path, want := range map[string]string{"persona/APPEND_SYSTEM.md": "be brief", "skills/brief/SKILL.md": "# brief"} {
		b, err := os.ReadFile(filepath.Join(dst, path))
		if err != nil || string(b) != want {
			t.Fatalf("%s: %q %v", path, b, err)
		}
		fi, _ := os.Stat(filepath.Join(dst, path))
		if fi.Mode().Perm() != 0444 {
			t.Fatalf("%s mode %v", path, fi.Mode())
		}
	}
	for _, d := range []string{dst, filepath.Join(dst, "skills"), filepath.Join(dst, "skills", "brief")} {
		if fi, _ := os.Stat(d); fi.Mode().Perm() != 0555 {
			t.Fatalf("%s mode %v", d, fi.Mode())
		}
	}
	var listed struct{ Versions []AgentDataVersion }
	b, _ := os.ReadFile(filepath.Join(dst, "versions.json"))
	if err := json.Unmarshal(b, &listed); err != nil || len(listed.Versions) != 2 || listed.Versions[0].DataHash != "0xd1" {
		t.Fatalf("versions.json %s %v", b, err)
	}
	write(filepath.Join(persona, "APPEND_SYSTEM.md"), "changed later")
	if b, _ := os.ReadFile(filepath.Join(dst, "persona", "APPEND_SYSTEM.md")); string(b) != "be brief" {
		t.Fatal("the job's copy follows its source")
	}
	// Only regular files and directories are copied.
	if err := os.Symlink("/etc/passwd", filepath.Join(skills, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := stageAgentData(filepath.Join(t.TempDir(), "agent-data"), parts); err == nil {
		t.Fatal("a link in the source was copied")
	}
}

// A worker reading agent data learns the owner its memories' trust is
// checked against; the staged copy's place comes first.
func TestAgentDataEnvNamesTheOwner(t *testing.T) {
	const owner = "0xabcdef0000000000000000000000000000000001"
	got := (&Manager{owner: owner}).agentDataEnv("/task/agent-data")
	if strings.Join(got, " ") != "SEAL_AGENT_DATA=/task/agent-data SEAL_OWNER="+owner {
		t.Fatalf("env %v", got)
	}
	if got := (&Manager{}).agentDataEnv("/d"); len(got) != 1 {
		t.Fatalf("an empty owner was passed: %v", got)
	}
}

// A temporary worker of a release with the grant is refused when the
// runtime has no provider, never started without its data.
func TestAgentDataWithoutAProviderFailsTheWorker(t *testing.T) {
	m := &Manager{}
	if _, err := m.stageAgentDataFor(t.Context(), AgentDataGrant{Persona: true}, filepath.Join(t.TempDir(), "a")); err == nil {
		t.Fatal("staged agent data without a provider")
	}
}

const agentDataFixture = `import os,sys,json,http.server,socket
sys.stdin.read()
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_POST(self):
  self.rfile.read(int(self.headers.get('content-length',0)))
  root=os.environ.get('SEAL_AGENT_DATA','')
  out={'owner':os.environ.get('SEAL_OWNER'),'kinds':sorted(os.listdir(root)) if root else [],
   'memory':sorted(os.listdir(os.path.join(root,'memory-public'))) if root else []}
  self.send_response(200);self.end_headers();self.wfile.write(json.dumps(out).encode())
class Server(http.server.HTTPServer):
 address_family=socket.AF_UNIX
 def server_bind(self): self.socket.bind(self.server_address);self.server_name='task';self.server_port=0
Server(os.environ['MCP_SOCKET'],Handler).serve_forever()
`

// A request worker of a release granted public memory reads the staged
// memory-public/ copy and learns the owner (SEAL_OWNER) that decides which
// of those memories are trusted.
func TestAgentDataWorkerGetsPublicMemoryAndOwner(t *testing.T) {
	root(t)
	if os.Getenv("SEALED_SERVICE_TESTS") != "1" {
		t.Skip("set SEALED_SERVICE_TESTS=1 as root on a kernel with Landlock ABI 6")
	}
	src := t.TempDir()
	for name, body := range map[string]string{"MEMORY.md": "- [freeze](freeze.md) — release freeze\n", "freeze.md": "---\nname: freeze\n---\nfreeze starts 2026-11-24\n"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	const owner = "0xabcdef0000000000000000000000000000000001"
	var asked AgentDataGrant
	m, err := NewWithOptions(filepath.Join(t.TempDir(), "services"), owner+":identity", Options{
		SkipResourceLimitsForTests: true,
		Owner:                      owner,
		AgentData: func(_ context.Context, g AgentDataGrant) ([]AgentDataPart, func(), error) {
			asked = g
			return []AgentDataPart{{Dir: src, Version: AgentDataVersion{Kind: AgentDataPublicMemory, ContentHash: "c", DataHash: "0xd", SnapshotHash: "s", Files: 2}}}, func() {}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	man := manifest("task", agentDataFixture)
	man.AgentData = &AgentDataGrant{PublicMemory: true}
	if _, err := m.Publish(man); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(man.ID); err != nil {
		t.Fatal(err)
	}
	resp, err := m.HTTPClient("task").Do(taskRequest(context.Background(), "x", 0, testServiceVersion(m, "task")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var got struct {
		Owner  string
		Kinds  []string
		Memory []string
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("status %d body %q: %v", resp.StatusCode, body, err)
	}
	if !asked.PublicMemory || asked.Persona || asked.Skills {
		t.Fatalf("grant asked %+v", asked)
	}
	if got.Owner != owner || strings.Join(got.Kinds, ",") != "memory-public,versions.json" || strings.Join(got.Memory, ",") != "MEMORY.md,freeze.md" {
		t.Fatalf("worker saw %+v", got)
	}
}
