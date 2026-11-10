package framework

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// git, given only the credential environment as a harness that drops
// credential-shaped names passes it on, asks the credential socket for
// github.com and gets the placeholder; for another host it gets nothing and
// carries on.
func TestGitCredentialHelperThroughGit(t *testing.T) {
	for _, bin := range []string{"git", "curl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	sock := filepath.Join(t.TempDir(), "cred.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/credentials/git" && r.URL.Query().Get("host") == "github.com" {
				_, _ = w.Write([]byte("username=x-access-token\npassword=[[credential:gh]]\n"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
	}()
	gitConfig := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(gitConfig, GitConfig(), 0o644); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, kv := range (RuntimeContext{CredProxy: "http://127.0.0.1:1/t", CredHTTPSProxy: "http://agent:t@127.0.0.1:1", CredSock: sock, CredGitConfig: gitConfig}).CredentialEnv() {
		// 0g-harness's tools (dsh) never see these names.
		if name, _, _ := strings.Cut(kv, "="); !regexp.MustCompile(`(?i)KEY|PASSWORD|SECRET|TOKEN`).MatchString(name) {
			env = append(env, kv)
		}
	}
	fill := func(host string) string {
		cmd := exec.Command("git", "credential", "fill")
		cmd.Env = append([]string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH"), "GIT_TERMINAL_PROMPT=0"}, env...)
		cmd.Stdin = strings.NewReader("protocol=https\nhost=" + host + "\n\n")
		out, _ := cmd.Output()
		return string(out)
	}
	if got := fill("github.com"); !strings.Contains(got, "username=x-access-token") || !strings.Contains(got, "password=[[credential:gh]]") {
		t.Fatalf("git got %q", got)
	}
	if got := fill("gitlab.com"); strings.Contains(got, "credential:") {
		t.Fatalf("another host got %q", got)
	}
}
