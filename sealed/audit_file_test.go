package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/credentials"
	"seal-verify/internal/framework"
)

// An audit file this boot cannot read (here, over maxAuditFile) is not
// taken for "nothing persisted": the flush must not write over it.
func TestUnreadableAuditFileIsKept(t *testing.T) {
	old := framework.StateDir
	framework.StateDir = t.TempDir()
	defer func() { framework.StateDir = old }()
	owner := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	f := credentials.AuditFile{Owner: owner}
	f.Records = append(f.Records, credentials.AuditRecord{Time: time.Now(), Op: "sign transaction", Names: []string{"wallet"}, Result: "signed: evidence"})
	host := strings.Repeat("a", 17<<10)
	for i := 0; i < 1000; i++ {
		f.Records = append(f.Records, credentials.AuditRecord{Time: time.Now(), Op: "inject", Names: []string{"nope"}, Host: host, Result: "unknown_entry"})
	}
	b, _ := json.Marshal(f)
	if len(b) <= maxAuditFile {
		t.Fatalf("the file is %d bytes, not over %d", len(b), maxAuditFile)
	}
	_ = os.MkdirAll(credStateDir(), 0o700)
	if err := os.WriteFile(filepath.Join(credStateDir(), "audit.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadAudit(); ok {
		t.Fatal("an unreadable audit log was taken for nothing persisted, so the first flush would overwrite it")
	}
}
