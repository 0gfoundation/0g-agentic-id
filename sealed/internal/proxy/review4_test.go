package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/credentials"
	"seal-verify/internal/credproxy"
	"seal-verify/internal/state"
)

// An owner route whose lookup a later one overtook, naming someone else,
// does not serve.
func TestRouteOvertakenLookupNotServed(t *testing.T) {
	signA, ownerA := mustKey(t)
	_, ownerB := mustKey(t)
	a, b := common.HexToAddress(ownerA), common.HexToAddress(ownerB)

	var live atomic.Value
	live.Store(a)
	store := credentials.NewStore(credentials.Env{
		SealID:    "0xdeadbeef",
		LiveOwner: func(context.Context) (common.Address, error) { return live.Load().(common.Address), nil },
		Logf:      t.Logf,
	}, credproxy.NewRegistry())
	if err := store.RefreshOwner(context.Background()); err != nil { // A is the owner
		t.Fatal(err)
	}

	ag := state.New()
	ag.Set([]byte{1}, "http://127.0.0.1:1", "deadbeef", ownerA, "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag, publicURL: credAudience}
	s.SetCredentials(store)
	inFlight := make(chan struct{})
	release := make(chan struct{})
	s.SetLiveOwner(func(ctx context.Context) (string, error) {
		// The route's chain read, answered as of the block before the
		// transfer (it began first).
		close(inFlight)
		<-release
		return ownerA, nil
	})

	done := make(chan *httptest.ResponseRecorder)
	go func() {
		w := httptest.NewRecorder()
		s.handleCredentialPending(w, credReq(signA, http.MethodGet, "/_seal/credentials/pending", "0GSealCredPending", ""))
		done <- w
	}()
	<-inFlight
	// The transfer lands; the watcher's lookup (begun later) records B and
	// clears A's state; the agent then opens a request under B.
	live.Store(b)
	if err := store.RefreshOwner(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, perr := store.Request("add", "b-only-entry", nil, "asked after the transfer"); perr != nil {
		t.Fatal(perr)
	}
	close(release)
	w := <-done
	t.Logf("HTTP %d %s", w.Code, strings.TrimSpace(w.Body.String()))
	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "b-only-entry") {
		t.Fatalf("a request authorized by the previous owner's (superseded) lookup was served the new owner's state")
	}
}

// A trailer whose name holds a value, in any letter case, is not announced
// or relayed.
func TestTrailerNamesWithValueDropped(t *testing.T) {
	for _, value := range []string{
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // '/' keeps the transport from canonicalizing it
		"deadbeefcafebabe0123456789abcdef",         // canonicalized to "Deadbeef…"
	} {
		t.Run(value[:8], func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", value)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"no upgrade"}`))
			}))
			defer backend.Close()

			ag := state.New()
			ag.Set([]byte{1}, backend.URL, "deadbeef", "0x00", "1", "0x00", "1", "0x00", "")
			s := &Server{agent: ag}
			s.SetScrubber(scrubValues{value})
			s.services = []ServiceEntry{{Path: "/api/echo", Method: http.MethodGet, Backend: backend.URL}}
			front := httptest.NewServer(http.HandlerFunc(s.handleProxy))
			defer front.Close()

			conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_, _ = conn.Write([]byte("GET /api/echo HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			br := bufio.NewReader(conn)
			var head []string
			for {
				line, err := br.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
				head = append(head, strings.TrimSpace(line))
			}
			t.Logf("response head: %q", head)
			for _, h := range head {
				if strings.Contains(strings.ToLower(h), strings.ToLower(value[1:])) {
					t.Fatalf("the value (letter case aside) left in the response head: %q", h)
				}
			}
		})
	}
}
