package servicesandbox

import (
	"reflect"
	"testing"

	"seal-verify/internal/serviceidentity"
)

func testPolicy() Policy {
	return Policy{
		UID:        serviceidentity.Base + 42,
		ReadExec:   []string{"/usr", "/opt/release"},
		ReadOnly:   []string{"/etc/hosts"},
		Devices:    []string{"/dev/null"},
		SocketDirs: []string{"/var/lib/svc/t/run"},
		ReadWrite:  []string{"/var/lib/svc/t/work", "/var/lib/svc/t/tmp"},
		Dir:        "/opt/release",
		Env:        []string{"HOME=/var/lib/svc/t/work", "MCP_SOCKET=/var/lib/svc/t/run/service.sock"},
		Program:    "/usr/bin/python3",
		Args:       []string{"server.py", "--flag=x"},
		Limits:     Limits{AddressSpace: 8 << 30, Processes: 64, Files: 256, FileSize: 64 << 20},
	}
}

func TestLauncherArgsRoundTrip(t *testing.T) {
	p := testPolicy()
	args := p.LauncherArgs()
	if args[0] != "run" {
		t.Fatal("mode missing")
	}
	got, err := ParseRun(args[1:])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("round trip changed the policy:\n got %+v\nwant %+v", got, p)
	}
}

func TestPolicyRefusesForeignOrLoosePaths(t *testing.T) {
	for name, mutate := range map[string]func(*Policy){
		"root identity":     func(p *Policy) { p.UID = 0 },
		"agent identity":    func(p *Policy) { p.UID = 1000 },
		"nobody":            func(p *Policy) { p.UID = 65534 },
		"relative path":     func(p *Policy) { p.ReadExec = append(p.ReadExec, "usr") },
		"unclean path":      func(p *Policy) { p.ReadWrite = append(p.ReadWrite, "/var/lib/../root") },
		"whole filesystem":  func(p *Policy) { p.ReadOnly = append(p.ReadOnly, "/") },
		"relative program":  func(p *Policy) { p.Program = "python3" },
		"lower-case env":    func(p *Policy) { p.Env = append(p.Env, "home=/root") },
		"env without value": func(p *Policy) { p.Env = append(p.Env, "HOME") },
		"nul in argument":   func(p *Policy) { p.Args = append(p.Args, "a\x00b") },
	} {
		p := testPolicy()
		mutate(&p)
		if p.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseRun([]string{"--uid=20001", "--chdir=/", "--rx=/usr"}); err == nil {
		t.Error("accepted a policy without a program")
	}
	if _, err := ParseRun([]string{"--bogus=1", "--", "/bin/true"}); err == nil {
		t.Error("accepted an unknown flag")
	}
}
