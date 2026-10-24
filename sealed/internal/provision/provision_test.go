package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	eciesgo "github.com/ecies/go/v2"
)

func TestProvisionRequiresEncryptedBootReceipt(t *testing.T) {
	containerKey := make([]byte, 32)
	containerKey[31] = 7
	priv := eciesgo.NewPrivateKeyFromBytes(containerKey)
	seal := make([]byte, 32)
	seal[31] = 9
	encrypt := func(raw []byte) string {
		ct, err := eciesgo.Encrypt(priv.PublicKey, raw)
		if err != nil {
			t.Fatal(err)
		}
		return "0x" + hex.EncodeToString(ct)
	}
	keyCT := encrypt(seal)
	receiptCT := encrypt([]byte(`{"token":"current-boot"}`))
	settingsCT := encrypt([]byte(`{"model":"m"}`))
	for _, test := range []struct {
		name, receipt string
		retry         bool
		ok            bool
	}{
		{"modern", receiptCT, false, true},
		{"create-bookkeeping-retry", receiptCT, true, true},
		{"old-server", "", false, false},
		{"bad-ciphertext", "0x1234", false, false},
		{"empty-token", encrypt([]byte(`{"token":""}`)), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			var firstClaim string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_ = json.NewEncoder(w).Encode(map[string]int{"generation": 1})
					return
				}
				calls++
				raw, _ := io.ReadAll(r.Body)
				if firstClaim == "" {
					firstClaim = string(raw)
				} else if firstClaim != string(raw) {
					t.Error("bookkeeping retry changed its boot claim")
				}
				var proof struct {
					Seal       string `json:"seal_id"`
					Generation int64  `json:"boot_generation"`
					Ticket     string `json:"boot_ticket"`
					ID         string `json:"boot_id"`
					Started    int64  `json:"boot_started_at"`
					Signature  string `json:"container_signature"`
				}
				if err := json.Unmarshal(raw, &proof); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				id, _ := hex.DecodeString(strings.TrimPrefix(proof.ID, "0x"))
				sig, _ := hex.DecodeString(strings.TrimPrefix(proof.Signature, "0x"))
				if len(sig) != 65 {
					t.Error("invalid container signature")
					w.WriteHeader(400)
					return
				}
				sig[64] -= 27
				canonical := bootMessage(strings.TrimPrefix(proof.Seal, "0x"), proof.Generation, sha256.Sum256([]byte(proof.Ticket)), id, proof.Started)
				recovered, err := crypto.SigToPub(crypto.Keccak256([]byte(canonical)), sig)
				expected, _ := crypto.ToECDSA(containerKey)
				if err != nil || crypto.PubkeyToAddress(*recovered) != crypto.PubkeyToAddress(expected.PublicKey) {
					t.Error("container private-key proof failed")
					w.WriteHeader(400)
					return
				}
				var req map[string]any
				if err := json.Unmarshal(raw, &req); err != nil {
					t.Error(err)
				}
				if req["status_binding_scheme"] != "agentdna-status-v2" {
					t.Error("missing binding negotiation")
				}
				if test.retry && calls == 1 {
					w.WriteHeader(http.StatusConflict)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"encrypted_agent_seal_priv": keyCT, "encrypted_settings": settingsCT, "encrypted_status_binding": test.receipt})
			}))
			defer srv.Close()
			got := FromAttestor(srv.URL, containerKey, Attestation{SealID: strings.Repeat("aa", 32)}, strings.Repeat("11", 32))
			if test.ok {
				if hex.EncodeToString(got.AgentSealPriv) != hex.EncodeToString(seal) || got.StatusToken != "current-boot" || string(got.Settings) != `{"model":"m"}` {
					t.Fatal("provision payload mismatch")
				}
			} else if got.AgentSealPriv != nil {
				t.Fatal("accepted boot without receipt")
			}
			wantCalls := 1
			if test.retry {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("calls=%d want %d", calls, wantCalls)
			}
		})
	}
}

func TestBootProofCrossLanguage(t *testing.T) {
	raw, err := os.ReadFile("../inference/testdata/boot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Canonical string `json:"canonical"`
		Request   struct {
			Seal       string `json:"seal_id"`
			Generation int64  `json:"boot_generation"`
			Ticket     string `json:"boot_ticket"`
			ID         string `json:"boot_id"`
			Started    int64  `json:"boot_started_at"`
		} `json:"request"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	id, _ := hex.DecodeString(strings.TrimPrefix(fixture.Request.ID, "0x"))
	got := bootMessage(strings.TrimPrefix(fixture.Request.Seal, "0x"), fixture.Request.Generation, sha256.Sum256([]byte(fixture.Request.Ticket)), id, fixture.Request.Started)
	if got != fixture.Canonical {
		t.Fatalf("boot canonical differs: %s", got)
	}
}
