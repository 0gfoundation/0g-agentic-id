package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/framework"
	"seal-verify/internal/state"
)

const testAgenticID = "0x00000000000000000000000000000000000000A1"

// declaringAdapter declares the runtime's signing rules and tools, as
// 0g-harness does; the embedded nil Framework panics if anything else is
// called.
type declaringAdapter struct{ framework.Framework }

func (declaringAdapter) AppliesSigningRules() bool { return true }
func (declaringAdapter) ServesRuntimeTools() bool  { return true }

// harnessAdapter is a declaringAdapter that runs from a harness package
// (framework.LayeredRuntime), as 0g-harness does.
type harnessAdapter struct{ declaringAdapter }

func (harnessAdapter) UseHarness(string, string)            {}
func (harnessAdapter) HarnessHash() string                  { return "" }
func (harnessAdapter) InferenceTarget() (url, model string) { return "", "" }

// rulesServer is signServer bound to an adapter that declares them.
func rulesServer(t *testing.T) (*Server, common.Address) {
	t.Helper()
	s, addr := signServer(t)
	s.adapter = declaringAdapter{}
	return s, addr
}

// postSock sends body to path on the sign socket's mux.
func postSock(t *testing.T, s *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	mux, _ := s.signSocketMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw)))
	return rec
}

func lastRecord(t *testing.T, s *Server) SignRecord {
	t.Helper()
	recs := s.signLog.since(-1)
	if len(recs) == 0 {
		t.Fatal("nothing recorded")
	}
	return recs[len(recs)-1]
}

// Every signature the socket makes is recorded with what identifies it.
func TestSignLog_RecordsEachShape(t *testing.T) {
	s, _ := rulesServer(t)

	if rec := postSock(t, s, "/sign/personal_sign", map[string]string{"message": "hello"}); rec.Code != 200 {
		t.Fatalf("personal_sign: %d %s", rec.Code, rec.Body)
	}
	r := lastRecord(t, s)
	if r.Kind != "personal_sign" || r.Result != "signed" || r.Text != "hello" || r.Length == nil || *r.Length != 5 || r.MsgHash == "" {
		t.Fatalf("personal_sign record: %+v", r)
	}

	if rec := postSock(t, s, "/sign/personal_sign", map[string]string{"message_hex": "0xff00"}); rec.Code != 200 {
		t.Fatalf("personal_sign hex: %d", rec.Code)
	}
	if r := lastRecord(t, s); r.Text != "" || *r.Length != 2 {
		t.Fatalf("bytes that are not text are not kept as text: %+v", r)
	}

	td := map[string]any{
		"types": map[string]any{
			"EIP712Domain": []map[string]string{{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}},
			"Mail":         []map[string]string{{"name": "contents", "type": "string"}},
		},
		"primaryType": "Mail",
		"domain":      map[string]any{"name": "Test", "chainId": 16602, "verifyingContract": "0x0000000000000000000000000000000000000001"},
		"message":     map[string]any{"contents": "hi"},
	}
	if rec := postSock(t, s, "/sign/typed_data", td); rec.Code != 200 {
		t.Fatalf("typed_data: %d %s", rec.Code, rec.Body)
	}
	r = lastRecord(t, s)
	if r.Kind != "typed_data" || r.PrimaryType != "Mail" || r.Digest == "" || r.Domain["name"] != "Test" || r.Domain["chain_id"] != "16602" {
		t.Fatalf("typed_data record: %+v", r)
	}

	tx := map[string]any{"chain_id": "16602", "nonce": 7, "to": "0x0000000000000000000000000000000000000002", "value": "1000", "data": "0xa9059cbb00", "gas_limit": 21000, "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1"}
	rec := postSock(t, s, "/sign/transaction", tx)
	if rec.Code != 200 {
		t.Fatalf("transaction: %d %s", rec.Code, rec.Body)
	}
	r = lastRecord(t, s)
	if r.Kind != "transaction" || r.Result != "signed" || r.ChainID != "16602" || r.To != "0x0000000000000000000000000000000000000002" ||
		r.Value != "1000" || *r.Nonce != 7 || r.Selector != "0xa9059cbb" || *r.DataLen != 5 || r.TxHash == "" || r.Create {
		t.Fatalf("transaction record: %+v", r)
	}

	recs := s.signLog.since(-1)
	for i, r := range recs {
		if r.Seq != uint64(i) {
			t.Fatalf("records are numbered in order: %+v", recs)
		}
	}
	if got := s.signLog.since(int64(len(recs) - 2)); len(got) != 1 || got[0].Seq != uint64(len(recs)-1) {
		t.Fatalf("since: %+v", got)
	}
}

// A request the socket does not sign leaves no "signed" record.
func TestSignLog_BadRequestsAreNotSignatures(t *testing.T) {
	s, _ := rulesServer(t)
	if rec := postSock(t, s, "/sign/personal_sign", map[string]string{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty message: %d", rec.Code)
	}
	if n := len(s.signLog.since(-1)); n != 0 {
		t.Fatalf("recorded %d", n)
	}
}

func iDataCall(t *testing.T, method string) string {
	t.Helper()
	sel := map[string]string{
		"update":   "update(uint256,(string,bytes32)[],bytes[])",
		"updateAt": "updateAt(uint256,uint256,(string,bytes32),bytes)",
	}[method]
	return "0x" + common.Bytes2Hex(crypto.Keccak256([]byte(sel))[:4]) + strings.Repeat("00", 32)
}

// agentSeal does not sign AgenticID update/updateAt: the socket answers 403
// and records the refusal. Other calls to AgenticID, and the same selector
// to another contract, are signed.
func TestSignRules_RefusesIDataWrites(t *testing.T) {
	s, _ := rulesServer(t)
	s.SetAgenticID(testAgenticID)
	base := map[string]any{"chain_id": "16602", "nonce": 1, "gas_limit": 100000, "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1"}
	with := func(to, data string) map[string]any {
		m := map[string]any{"to": to, "data": data}
		for k, v := range base {
			m[k] = v
		}
		return m
	}
	for _, method := range []string{"update", "updateAt"} {
		for _, to := range []string{testAgenticID, strings.ToLower(testAgenticID)} {
			rec := postSock(t, s, "/sign/transaction", with(to, iDataCall(t, method)))
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "AgenticID "+method) {
				t.Fatalf("%s to %s: %d %s", method, to, rec.Code, rec.Body)
			}
			r := lastRecord(t, s)
			if r.Result != "refused" || r.Reason == "" || !strings.EqualFold(r.To, testAgenticID) || r.ChainID != "16602" {
				t.Fatalf("refusal record: %+v", r)
			}
		}
	}
	// Legacy too: the rule reads the transaction, not its type.
	legacy := with(testAgenticID, iDataCall(t, "update"))
	legacy["type"], legacy["gas_price"] = "legacy", "3"
	if rec := postSock(t, s, "/sign/transaction", legacy); rec.Code != http.StatusForbidden {
		t.Fatalf("legacy update: %d", rec.Code)
	}
	if r := lastRecord(t, s); r.ChainID != "16602" {
		t.Fatalf("a refused legacy transaction keeps the request's chain id: %+v", r)
	}
	for name, tx := range map[string]map[string]any{
		"another AgenticID method": with(testAgenticID, "0x12345678"),
		"update to another target": with("0x0000000000000000000000000000000000000002", iDataCall(t, "update")),
		"plain transfer":           with(testAgenticID, ""),
	} {
		if rec := postSock(t, s, "/sign/transaction", tx); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// No AgenticID configured: the rule is off.
	s2, _ := rulesServer(t)
	if rec := postSock(t, s2, "/sign/transaction", with(testAgenticID, iDataCall(t, "update"))); rec.Code != http.StatusOK {
		t.Fatalf("rule without an address: %d", rec.Code)
	}
}

// The owner reads the record over /_seal/signatures, owner-signed.
func TestSignLog_OwnerReadsIt(t *testing.T) {
	sign, owner := mustKey(t)
	priv, _ := crypto.GenerateKey()
	ag := state.New()
	ag.Set(crypto.FromECDSA(priv), "http://127.0.0.1:1", "deadbeef", owner, "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag, adapter: declaringAdapter{}}
	postSock(t, s, "/sign/personal_sign", map[string]string{"message": "one"})
	postSock(t, s, "/sign/personal_sign", map[string]string{"message": "two"})

	get := func(query string, signer func(string) string) *httptest.ResponseRecorder {
		msg := fmt.Sprintf("0GSealSignatures:0xdeadbeef:%d:", time.Now().Unix())
		r := httptest.NewRequest(http.MethodGet, "/_seal/signatures"+query, nil)
		r.Header.Set("X-Auth-Message", msg)
		r.Header.Set("X-Auth-Signature", signer(msg))
		w := httptest.NewRecorder()
		s.handleSignatures(w, r)
		return w
	}
	w := get("", sign)
	var recs []SignRecord
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &recs) != nil || len(recs) != 2 || recs[1].Text != "two" {
		t.Fatalf("all: %d %s", w.Code, w.Body)
	}
	w = get("?after=0", sign)
	if json.Unmarshal(w.Body.Bytes(), &recs) != nil || len(recs) != 1 || recs[0].Text != "two" {
		t.Fatalf("after=0: %s", w.Body)
	}
	other, _ := mustKey(t)
	if w := get("", other); w.Code == http.StatusOK {
		t.Fatal("someone other than the owner read the record")
	}
	s.adapter = nil
	if w := get("", sign); w.Code != http.StatusNotFound {
		t.Fatalf("a framework without the signing rules has no record to read: %d", w.Code)
	}
}

// A framework that does not declare the signing rules signs as it always
// has: nothing recorded, nothing refused.
func TestSigningRules_OnlyWhereDeclared(t *testing.T) {
	s, _ := signServer(t)
	s.SetAgenticID(testAgenticID)
	postSock(t, s, "/sign/personal_sign", map[string]string{"message": "hi"})
	tx := map[string]any{"chain_id": "16602", "nonce": 1, "to": testAgenticID, "data": iDataCall(t, "update"), "gas_limit": 100000, "max_fee_per_gas": "2", "max_priority_fee_per_gas": "1"}
	if rec := postSock(t, s, "/sign/transaction", tx); rec.Code != http.StatusOK {
		t.Fatalf("an undeclared framework's transaction: %d %s", rec.Code, rec.Body)
	}
	if n := len(s.signLog.since(-1)); n != 0 {
		t.Fatalf("recorded %d for an undeclared framework", n)
	}
}

// The record survives a restart of sealed, and numbering goes on from it.
func TestSignLog_Persists(t *testing.T) {
	dir := t.TempDir()
	prev := framework.StateDir
	framework.StateDir = dir
	t.Cleanup(func() { framework.StateDir = prev })

	s, _ := rulesServer(t)
	s.EnableSignLog()
	postSock(t, s, "/sign/personal_sign", map[string]string{"message": "before"})
	s.signLog.flush()

	s2, _ := rulesServer(t)
	s2.EnableSignLog()
	postSock(t, s2, "/sign/personal_sign", map[string]string{"message": "after"})
	recs := s2.signLog.since(-1)
	if len(recs) != 2 || recs[0].Text != "before" || recs[1].Text != "after" || recs[1].Seq != 1 {
		t.Fatalf("restored: %+v", recs)
	}

	// A file that does not parse is left alone and not written over.
	if err := framework.WriteState(signLogStateFile, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	s3, _ := rulesServer(t)
	s3.EnableSignLog()
	postSock(t, s3, "/sign/personal_sign", map[string]string{"message": "x"})
	s3.signLog.flush()
	b, _ := framework.ReadState(signLogStateFile)
	if string(b) != "{not json" {
		t.Fatalf("an unreadable record was written over: %s", b)
	}
}

// The record keeps the last signLogMax entries.
func TestSignLog_Bounded(t *testing.T) {
	var l signLog
	for i := 0; i < signLogMax+5; i++ {
		l.add(SignRecord{Kind: "personal_sign"})
	}
	recs := l.since(-1)
	if len(recs) != signLogMax || recs[0].Seq != 5 {
		t.Fatalf("kept %d, first %d", len(recs), recs[0].Seq)
	}
}
