package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/openweb3/web3go"
	"github.com/sirupsen/logrus"
)

// fakeIndexer records the SplitableUpload call sdkUpload makes.
type fakeIndexer struct {
	calls  int
	w3     *web3go.Client
	size   int64
	opts   []transfer.UploadOption
	roots  []common.Hash
	err    error
	closed bool
}

func (f *fakeIndexer) SplitableUpload(_ context.Context, w3 *web3go.Client, data core.IterableData, option ...transfer.UploadOption) ([]common.Hash, []common.Hash, error) {
	f.calls++
	f.w3, f.size, f.opts = w3, data.Size(), option
	return nil, f.roots, f.err
}

func (f *fakeIndexer) Close() { f.closed = true }

// recordingSDK builds an sdk whose constructors record their arguments.
// newWeb3 still builds a real client (the SDK connects lazily, so nothing
// is dialled); newIndexer hands out idx.
type recordingSDK struct {
	web3URL    string
	web3Opt    web3go.ClientOption
	web3       *web3go.Client
	web3Err    error
	indexerURL string
	indexerOpt indexer.IndexerClientOption
	indexerErr error
	newIndexer int
	idx        *fakeIndexer
}

func (r *recordingSDK) sdk() sdk {
	return sdk{
		newWeb3: func(url string, opt web3go.ClientOption) (*web3go.Client, error) {
			r.web3URL, r.web3Opt = url, opt
			if r.web3Err != nil {
				return nil, r.web3Err
			}
			c, err := web3go.NewClientWithOption(url, opt)
			r.web3 = c
			return c, err
		},
		newIndexer: func(url string, opt indexer.IndexerClientOption) (splitUploader, error) {
			r.newIndexer++
			r.indexerURL, r.indexerOpt = url, opt
			if r.indexerErr != nil {
				return nil, r.indexerErr
			}
			return r.idx, nil
		},
	}
}

func uploadInput(t *testing.T, content string) options {
	t.Helper()
	file := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := parseFlags(sealedArgs(t, file), io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	return o
}

func testKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()
	priv, err := crypto.HexToECDSA(testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return priv, crypto.PubkeyToAddress(priv.PublicKey)
}

// TestSDKUpload_WiresTheCLIPath checks every argument sdkUpload hands the
// SDK on sealed's invocation, against what `0g-storage-client upload
// --indexer` passes (cmd/upload.go, cmd/root.go and
// common/blockchain/rpc.go at the pinned version; TestCLISource_Unchanged
// notices when those change).
func TestSDKUpload_WiresTheCLIPath(t *testing.T) {
	const content = "ciphertext bytes"
	o := uploadInput(t, content)
	priv, addr := testKey(t)
	root := common.HexToHash("0xab")
	r := &recordingSDK{idx: &fakeIndexer{roots: []common.Hash{root}}}

	roots, err := r.sdk().upload(context.Background(), o, priv)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if len(roots) != 1 || roots[0] != root {
		t.Fatalf("roots = %v, want [%s]", roots, root)
	}

	// Fullnode client: blockchain.NewWeb3 with the CLI's provider option
	// and a signer manager holding exactly the key's signer.
	if r.web3URL != sealedRPC {
		t.Errorf("fullnode URL = %q, want %q", r.web3URL, sealedRPC)
	}
	if !reflect.DeepEqual(r.web3Opt.Option, providerOption()) {
		t.Errorf("fullnode provider option = %+v, want %+v", r.web3Opt.Option, providerOption())
	}
	if sm := r.web3Opt.SignerManager; sm == nil {
		t.Error("fullnode client has no signer manager")
	} else if list := sm.List(); len(list) != 1 || list[0].Address() != addr {
		t.Errorf("signer manager holds %d signers, want exactly %s", len(list), addr)
	}

	// Indexer client: the CLI's option with the default (empty) contract
	// addresses and one routine per CPU.
	if r.indexerURL != sealedIndexer {
		t.Errorf("indexer URL = %q, want %q", r.indexerURL, sealedIndexer)
	}
	wantIdx := indexer.IndexerClientOption{
		ProviderOption: providerOption(),
		LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
		Routines:       runtime.GOMAXPROCS(0),
		Contract:       &transfer.ContractAddress{},
	}
	if !reflect.DeepEqual(r.indexerOpt, wantIdx) {
		t.Errorf("indexer option = %+v, want %+v", r.indexerOpt, wantIdx)
	}

	// The upload itself.
	idx := r.idx
	if idx.calls != 1 {
		t.Fatalf("SplitableUpload called %d times, want 1", idx.calls)
	}
	if idx.w3 == nil || idx.w3 != r.web3 {
		t.Error("SplitableUpload did not get the fullnode client sdkUpload built")
	}
	if idx.size != int64(len(content)) {
		t.Errorf("uploaded data size = %d, want %d (the --file content)", idx.size, len(content))
	}
	if len(idx.opts) != 1 || !reflect.DeepEqual(idx.opts[0], uploadOption(o, addr)) {
		t.Errorf("upload options = %+v, want exactly [%+v]", idx.opts, uploadOption(o, addr))
	}
	if !idx.closed {
		t.Error("indexer client not closed")
	}
}

func TestSDKUpload_Errors(t *testing.T) {
	priv, _ := testKey(t)
	boom := errors.New("boom")

	t.Run("fullnode client", func(t *testing.T) {
		r := &recordingSDK{web3Err: boom, idx: &fakeIndexer{}}
		_, err := r.sdk().upload(context.Background(), uploadInput(t, "x"), priv)
		if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "connect to fullnode: ") {
			t.Fatalf("err = %v", err)
		}
		if r.newIndexer != 0 {
			t.Fatal("indexer client built after the fullnode client failed")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		r := &recordingSDK{idx: &fakeIndexer{}}
		o := uploadInput(t, "x")
		o.file = filepath.Join(t.TempDir(), "missing.bin")
		_, err := r.sdk().upload(context.Background(), o, priv)
		if err == nil || !strings.HasPrefix(err.Error(), "open file: ") {
			t.Fatalf("err = %v", err)
		}
		if r.newIndexer != 0 {
			t.Fatal("indexer client built for a missing file")
		}
	})
	t.Run("indexer client", func(t *testing.T) {
		r := &recordingSDK{indexerErr: boom, idx: &fakeIndexer{}}
		_, err := r.sdk().upload(context.Background(), uploadInput(t, "x"), priv)
		if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "initialize indexer client: ") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("upload", func(t *testing.T) {
		r := &recordingSDK{idx: &fakeIndexer{err: boom}}
		_, err := r.sdk().upload(context.Background(), uploadInput(t, "x"), priv)
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the SDK's error", err)
		}
		if !r.idx.closed {
			t.Fatal("indexer client not closed after a failed upload")
		}
	})
}

// TestStorageSDK_BuildsRealClientsOffline: the production constructors
// build the SDK's own clients without contacting either endpoint.
func TestStorageSDK_BuildsRealClientsOffline(t *testing.T) {
	w3, err := storageSDK.newWeb3("http://127.0.0.1:1", web3go.ClientOption{Option: providerOption()})
	if err != nil {
		t.Fatalf("newWeb3: %v", err)
	}
	w3.Close()
	c, err := storageSDK.newIndexer("http://127.0.0.1:1", indexer.IndexerClientOption{ProviderOption: providerOption()})
	if err != nil {
		t.Fatalf("newIndexer: %v", err)
	}
	if _, ok := c.(*indexer.Client); !ok {
		t.Fatalf("newIndexer built a %T, want *indexer.Client", c)
	}
	c.Close()
}

// cliSourceSHA256 pins the files of the pinned 0g-storage-client that
// define what `0g-storage-client upload --indexer` does: its flags and
// their defaults, the provider defaults, how it builds the fullnode client
// and the SDK calls it makes. main.go mirrors them (uploadOption,
// providerOption, sdkUpload) and was checked against exactly these
// contents.
var cliSourceSHA256 = map[string]string{
	"cmd/upload.go":            "517b7b45d6e38abc25dc1102d05114bc607a3eb040a44d0007c1a745aa30385c",
	"cmd/root.go":              "ab82833a59c13a7cd613eaaa274e3b3f226db4786be33cb0b009f61757a06182",
	"common/blockchain/rpc.go": "c32e90b453829a607fc1369c3102d64effa78d2069fa778a32bfd9001d08fba1",
}

// TestCLISource_Unchanged turns the "re-check main.go when bumping the
// SDK" step (go.mod) into a failing test: after a bump that changes any of
// the files above, re-check uploadOption, providerOption and sdkUpload
// against them, then record the new hashes.
func TestCLISource_Unchanged(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	out, err := exec.Command(goBin, "list", "-m", "-f", "{{.Dir}}", "github.com/0gfoundation/0g-storage-client").Output()
	if err != nil {
		t.Fatalf("locate the pinned 0g-storage-client source: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatal("go list reported no source directory for 0g-storage-client (module not downloaded?)")
	}
	for rel, want := range cliSourceSHA256 {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("the pinned CLI's %s changed (sha256 %s): re-check uploadOption, providerOption and sdkUpload against it, then update cliSourceSHA256", rel, got)
		}
	}
}
