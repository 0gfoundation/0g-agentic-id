package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A disconnect overtaken by a change to the entry is not "not found": the
// owner learns the server may have revoked, and that nothing was forgotten.
func TestDisconnectOvertakenAnswersConflict(t *testing.T) {
	sign, owner := mustKey(t)
	s, _ := credServer(t, owner)
	w := httptest.NewRecorder()
	s.handleCredentialDisconnect(w, credReq(sign, http.MethodPost, "/_seal/credentials/disconnect", "0GSealCredDisconnect", `{"name":"moving"}`))
	var b struct {
		Code    string `json:"code"`
		Revoked bool   `json:"revoked"`
	}
	if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &b) != nil || b.Code != "changed" || !b.Revoked {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
}
