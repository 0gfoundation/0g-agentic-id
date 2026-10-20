// Owner session token: one owner signature (the /_seal/auth handshake) buys a
// short-lived bearer the owner's client sends as X-Seal-Session on the
// owner-only READ and CLEAR routes, instead of asking the wallet to sign again
// for every log read and every clear.
//
// Format: "<exp>.<owner>.<hex(hmac)>", HMAC-SHA256 under a per-process random
// key over "0GSealSession:0x<sealID>:<owner>:<exp>". The key never leaves
// memory, so a container restart invalidates every outstanding session — the
// client just signs /_seal/auth again.
//
// What it deliberately does NOT carry over from the signature path:
//
//   - Owner check: still LIVE on every use (resolveOwner), and the token's
//     owner must equal it. A session minted before a transfer dies the moment
//     the chain names a new owner, exactly like a signature would.
//   - Body digest: a session attests WHO is calling, not WHAT body was meant.
//     That is why it is accepted only where the body carries no meaning
//     (/log/agent reads; /_seal/clear, whose body is unused). Settings and
//     claim stay signature-only.
package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SessionHeader carries the owner session token.
const SessionHeader = "X-Seal-Session"

// sessionTTLSec bounds a session's life. An hour covers a working session
// without making a leaked token a long-lived credential.
const sessionTTLSec = 3600

func (s *Server) sessionMAC(sealID, owner string, exp int64) []byte {
	s.sessionOnce.Do(func() {
		s.sessionKey = make([]byte, 32)
		if _, err := rand.Read(s.sessionKey); err != nil {
			panic("proxy: session key: " + err.Error())
		}
	})
	m := hmac.New(sha256.New, s.sessionKey)
	fmt.Fprintf(m, "0GSealSession:0x%s:%s:%d", strings.ToLower(sealID), strings.ToLower(owner), exp)
	return m.Sum(nil)
}

// mintSession returns a token for owner, valid sessionTTLSec from now, and its
// expiry.
func (s *Server) mintSession(sealID, owner string, now int64) (string, int64) {
	exp := now + sessionTTLSec
	owner = strings.ToLower(owner)
	return fmt.Sprintf("%d.%s.%s", exp, owner, hex.EncodeToString(s.sessionMAC(sealID, owner, exp))), exp
}

// verifyOwner gates an owner-only route that accepts a session: a request
// carrying X-Seal-Session is checked as a session (and never falls back to a
// signature, so a bad token is a clear 401, not a confusing "missing
// X-Auth-Message"); any other request goes through verifyOwnerSig unchanged.
func (s *Server) verifyOwner(w http.ResponseWriter, r *http.Request, tag, sealID, cachedOwner, wantDigest string) bool {
	tok := r.Header.Get(SessionHeader)
	if tok == "" {
		_, ok := s.verifyOwnerSig(w, r, tag, sealID, cachedOwner, wantDigest)
		return ok
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		http.Error(w, SessionHeader+" must be <exp>.<owner>.<mac>", http.StatusUnauthorized)
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	mac, herr := hex.DecodeString(parts[2])
	if err != nil || herr != nil || !hmac.Equal(mac, s.sessionMAC(sealID, parts[1], exp)) {
		http.Error(w, "invalid session (the agent may have restarted): sign /_seal/auth again", http.StatusUnauthorized)
		return false
	}
	if time.Now().Unix() >= exp {
		http.Error(w, "session expired: sign /_seal/auth again", http.StatusUnauthorized)
		return false
	}
	owner, ok := s.resolveOwner(r.Context(), cachedOwner)
	if !ok {
		http.Error(w, "owner lookup unavailable, retry", http.StatusServiceUnavailable)
		return false
	}
	if !strings.EqualFold(parts[1], owner) {
		http.Error(w, "session owner is no longer the agent owner", http.StatusUnauthorized)
		return false
	}
	return true
}
