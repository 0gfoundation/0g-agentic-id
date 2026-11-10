package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/state"
)

// A lookup in flight when the container closed, answering the previous owner
// (read before the transfer, or from a lagging RPC node), opens nothing.
func TestStaleLookupKeepsTheContainerClosed(t *testing.T) {
	sellerSign, seller := mustKey(t)
	_, buyer := mustKey(t)
	s, _ := credServer(t, seller)
	s.SetBootOwner(seller)

	release := make(chan string)
	entered := make(chan struct{})
	s.SetLiveOwner(func(ctx context.Context) (string, error) {
		entered <- struct{}{}
		return <-release, nil
	})

	type result struct {
		ok   bool
		code int
	}
	done := make(chan result)
	go func() {
		w := httptest.NewRecorder()
		_, ok := s.verifyOwnerSig(w, credReq(sellerSign, http.MethodGet, "/_seal/auth", "0GSealAuth", ""), "0GSealAuth", "deadbeef", seller, "")
		done <- result{ok, w.Code}
	}()
	<-entered // the seller's lookup is in flight

	// The watcher (or the buyer's request) sees the transfer and locks.
	if locked, _ := s.ObserveOwner(buyer); !locked {
		t.Fatal("setup: the transfer did not lock")
	}
	// The in-flight lookup returns the pre-transfer answer.
	release <- seller
	r := <-done

	if r.ok {
		t.Errorf("the previous owner's request was served after the lock closed (HTTP %d)", r.code)
	}
	if !s.OwnerLocked() {
		t.Errorf("a stale lookup reopened the lock; every route is served again until the next lookup")
	}
}

// An upgraded (WebSocket) connection opened before the container closed is
// ended when it closes.
func TestOpenUpgradeEndsWhenClosed(t *testing.T) {
	// Upstream: answers 101, then echoes lines.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					io.WriteString(c, "echo:"+line)
				}
			}(c)
		}
	}()
	upstream := "http://" + up.Addr().String()

	_, owner := mustKey(t)
	_, buyer := mustKey(t)
	ag := state.New()
	ag.Set([]byte{1}, upstream, "deadbeef", owner, "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag, synth: newSynthHub()}
	s.fwRoutes = []framework.Route{{Prefix: "/v1/", Kind: "chat", Auth: "bearer"}}
	s.SetBootOwner(owner)

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/", s.handleProxy)
	front := httptest.NewServer(corsMiddleware(s.ownerGate(mux)))
	defer front.Close()

	c, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /v1/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", err, resp)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "before\n")
	if line, _ := br.ReadString('\n'); line != "echo:before\n" {
		t.Fatalf("before lock: %q", line)
	}

	// Transfer: the container locks; a fresh request is refused.
	if locked, _ := s.ObserveOwner(buyer); !locked {
		t.Fatal("setup: not locked")
	}
	if r, err := http.Get(front.URL + "/v1/chat/completions"); err != nil || r.StatusCode != http.StatusLocked {
		t.Fatalf("fresh request after lock: %v %v", err, r)
	}

	io.WriteString(c, "after\n")
	if line, _ := br.ReadString('\n'); line == "echo:after\n" {
		t.Errorf("an upgraded connection opened before the lock is still relayed after it")
	}
}

// Path spellings against the exempt routes: none reaches another handler
// while the container is closed.
func TestExemptPathVariants(t *testing.T) {
	_, owner := mustKey(t)
	_, buyer := mustKey(t)
	s, _ := credServer(t, owner)
	s.SetBootOwner(owner)
	s.ObserveOwner(buyer)

	hit := ""
	mux := http.NewServeMux()
	for _, p := range []string{"/healthz", "/log", "/log.html", "/log/agent", "/hello", "/_seal/auth", "/"} {
		p := p
		mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { hit = p; w.WriteHeader(200) })
	}
	front := httptest.NewServer(s.ownerGate(mux))
	defer front.Close()
	for _, raw := range []string{
		"/hello", "/hello?x=1", "/hell%6F", "/%68ello", "/hello/", "//hello", "/./hello", "/hello/../_seal/auth",
		"/hello%2F..%2F_seal%2Fauth", "/log/../_seal/auth", "/log%2Fagent", "/log/agent", "/HELLO", "/hello%00",
	} {
		hit = ""
		c, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", raw)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if hit != "" && hit != "/hello" && hit != "/healthz" && hit != "/log" && hit != "/log.html" {
			t.Errorf("%s reached %s while locked", raw, hit)
		}
		if hit == "" && (err != nil || resp.StatusCode != http.StatusLocked) {
			t.Errorf("%s: %v %v, want 423", raw, err, resp)
		}
	}
}

// An RPC answering ownerOf with the zero address (32 zero bytes decode
// without error) has not answered: the owner's container stays open.
func TestZeroAddressAnswerIsNoAnswer(t *testing.T) {
	_, owner := mustKey(t)
	s, _ := credServer(t, owner)
	s.SetLiveOwner(func(context.Context) (string, error) {
		return "0x0000000000000000000000000000000000000000", nil
	})
	s.SetBootOwner(owner)
	got, ok := s.resolveOwner(context.Background(), owner)
	if ok {
		if locked, _ := s.ObserveOwner(got); locked {
			t.Errorf("a zero-address answer locked the owner's container")
		}
	}
}
