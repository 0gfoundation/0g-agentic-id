package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/credentials"
	"seal-verify/internal/credproxy"
	"seal-verify/internal/framework"
)

// The inference key held by sealed: the framework calls the router through
// the proxy with the placeholder, the router gets the key, and what comes
// back carries the placeholder again. A prompt that quotes placeholders is
// relayed as it is.
func TestCredHoldServesTheInferenceKeyThroughTheProxy(t *testing.T) {
	var gotAuth, gotBody string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotAuth, gotBody = r.Header.Get("Authorization"), string(b)
		_, _ = io.WriteString(w, `{"echo":"`+r.Header.Get("Authorization")+`"}`)
	}))
	defer upstream.Close()

	reg := credproxy.NewRegistry()
	owner := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	store := credentials.NewStore(credentials.Env{LiveOwner: func(context.Context) (common.Address, error) { return owner, nil }}, reg)
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	srv := credproxy.New(credproxy.Config{
		Registry: reg, Token: "tok", UpstreamTLS: &tls.Config{RootCAs: pool},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = srv.Serve(ln) }()

	hold := credHold(store, "http://"+ln.Addr().String()+"/tok")
	base, placeholder, err := hold("inference", "https://example.com/v1",
		map[string]string{"Authorization": "Bearer {v}", "x-api-key": "{v}"}, []byte("sk-the-real-key"))
	if err != nil {
		t.Fatal(err)
	}
	if placeholder != "[[credential:sealed:inference]]" || !strings.HasSuffix(base, "/tok/https/example.com/v1") {
		t.Fatalf("base %q placeholder %q", base, placeholder)
	}
	prompt := `{"messages":[{"role":"system","content":"write [[credential:<name>]] where a key goes, e.g. [[credential:github]]"}]}`
	req, _ := http.NewRequest("POST", base+"/chat/completions", strings.NewReader(prompt))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || gotAuth != "Bearer sk-the-real-key" || gotBody != prompt {
		t.Fatalf("HTTP %d; router got %q, body intact %v", resp.StatusCode, gotAuth, gotBody == prompt)
	}
	if strings.Contains(string(out), "sk-the-real-key") || !strings.Contains(string(out), placeholder) {
		t.Fatalf("the key came back: %s", out)
	}
	// Nothing reveals it, and it goes with the owner.
	if _, cerr := store.Reveal(context.Background(), "sealed:inference", ""); cerr == nil || cerr.Code != "unknown_entry" {
		t.Fatalf("reveal: %v", cerr)
	}
	store.ObserveOwner(common.HexToAddress("0x00000000000000000000000000000000000000b2"))
	if reg.Get("sealed:inference") != nil {
		t.Fatal("held key outlived an owner change")
	}
	// A framework restart does not take it again: the harness starts
	// without it, not with the key itself.
	if _, _, err := hold("inference", "https://example.com/v1", map[string]string{"Authorization": "Bearer {v}"}, []byte("sk-the-real-key")); !errors.Is(err, framework.ErrCredHoldRefused) {
		t.Fatalf("held again after the owner changed: %v", err)
	}
	// Only an https base URL, and only under the sealed: prefix.
	if _, _, err := hold("x", "http://router.example/v1", nil, []byte("k")); err == nil {
		t.Fatal("a plain-http base URL was accepted")
	}
	if err := store.HoldSystem(&credproxy.Entry{Name: "inference", Hosts: []string{"a.example"}, Value: []byte("k")}); err == nil {
		t.Fatal("a held value without the sealed: prefix was accepted")
	}
}

// A provisioned set whose load failed only because the owner could not be
// looked up is tried again; one that does not check out is not.
func TestLoadProvisionedRetriesOnlyOwnerLookups(t *testing.T) {
	reg := credproxy.NewRegistry()
	down := credentials.NewStore(credentials.Env{LiveOwner: func(context.Context) (common.Address, error) {
		return common.Address{}, errors.New("rpc down")
	}}, reg)
	if loadProvisioned(down, credentialsBoot{}) {
		t.Fatal("a failed owner lookup was taken as final")
	}
	up := credentials.NewStore(credentials.Env{LiveOwner: func(context.Context) (common.Address, error) {
		return common.HexToAddress("0x00000000000000000000000000000000000000a1"), nil
	}}, reg)
	if !loadProvisioned(up, credentialsBoot{}) {
		t.Fatal("a set that does not check out was tried again")
	}
}
