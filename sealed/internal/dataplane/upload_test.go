package dataplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/contract"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	rpc "github.com/openweb3/go-rpc-provider"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/openweb3/web3go"
	"github.com/sirupsen/logrus"

	"seal-verify/internal/logger"
)

// Stand-ins for Upload's indexerURL and rpcURL parameters.
const (
	sealedIndexer = "http://indexer.example:5678"
	sealedRPC     = "http://rpc.example:8545"
)

func testKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()
	priv, err := crypto.HexToECDSA(testSealPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	return priv, crypto.PubkeyToAddress(priv.PublicKey)
}

// fakeIndexer records the SplitableUpload call upload makes. upload, when
// set, replaces the canned result.
type fakeIndexer struct {
	calls  int
	ctx    context.Context
	w3     *web3go.Client
	data   []byte
	opts   []transfer.UploadOption
	roots  []common.Hash
	err    error
	upload func(ctx context.Context, data core.IterableData) ([]common.Hash, error)
	closed bool
}

func (f *fakeIndexer) SplitableUpload(ctx context.Context, w3 *web3go.Client, data core.IterableData, option ...transfer.UploadOption) ([]common.Hash, []common.Hash, error) {
	f.calls++
	f.ctx, f.w3, f.opts = ctx, w3, option
	f.data = make([]byte, data.Size())
	if _, err := data.Read(f.data, 0); err != nil {
		return nil, nil, err
	}
	if f.upload != nil {
		roots, err := f.upload(ctx, data)
		return nil, roots, err
	}
	return nil, f.roots, f.err
}

func (f *fakeIndexer) Close() { f.closed = true }

// recordingSDK builds an sdk whose constructors record their arguments.
// newWeb3 still builds a real client (the SDK connects lazily, so nothing
// is dialled), after applying web3Tweak, if set, to its option; newIndexer
// hands out idx.
type recordingSDK struct {
	web3URL    string
	web3Opt    web3go.ClientOption
	web3Tweak  func(*web3go.ClientOption)
	web3       *web3go.Client
	web3Err    error
	newWeb3    int
	indexerURL string
	indexerOpt indexer.IndexerClientOption
	indexerErr error
	newIndexer int
	idx        *fakeIndexer
}

func (r *recordingSDK) sdk() sdk {
	return sdk{
		newWeb3: func(url string, opt web3go.ClientOption) (*web3go.Client, error) {
			r.newWeb3++
			r.web3URL, r.web3Opt = url, opt
			if r.web3Err != nil {
				return nil, r.web3Err
			}
			if r.web3Tweak != nil {
				r.web3Tweak(&opt)
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

// useSDK makes Upload use s for the rest of the test.
func useSDK(t *testing.T, s sdk) {
	t.Helper()
	prev := storageSDK
	storageSDK = s
	t.Cleanup(func() { storageSDK = prev })
}

// TestSDKUpload_WiresTheCLIPath checks every argument upload hands the SDK,
// against what `0g-storage-client upload --indexer` passes for the flags
// sealed used to give it (cmd/upload.go, cmd/root.go and
// common/blockchain/rpc.go at the pinned version; TestCLISource_Unchanged
// notices when those change).
func TestSDKUpload_WiresTheCLIPath(t *testing.T) {
	const content = "ciphertext bytes"
	priv, addr := testKey(t)
	root := common.HexToHash("0xab")
	r := &recordingSDK{idx: &fakeIndexer{roots: []common.Hash{root}}}
	log := logrus.New()

	roots, err := r.sdk().upload(context.Background(), sealedIndexer, sealedRPC, []byte(content), priv, log)
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
	// addresses and one routine per CPU, logging to the logger upload got
	// (the CLI passes logrus's package-level one).
	if r.indexerURL != sealedIndexer {
		t.Errorf("indexer URL = %q, want %q", r.indexerURL, sealedIndexer)
	}
	wantIdx := indexer.IndexerClientOption{
		ProviderOption: providerOption(),
		LogOption:      zg_common.LogOption{Logger: log},
		Routines:       runtime.GOMAXPROCS(0),
		Contract:       &transfer.ContractAddress{},
	}
	if !reflect.DeepEqual(r.indexerOpt, wantIdx) || r.indexerOpt.LogOption.Logger != log {
		t.Errorf("indexer option = %+v, want %+v", r.indexerOpt, wantIdx)
	}

	// The upload itself.
	idx := r.idx
	if idx.calls != 1 {
		t.Fatalf("SplitableUpload called %d times, want 1", idx.calls)
	}
	if idx.w3 == nil || idx.w3 != r.web3 {
		t.Error("SplitableUpload did not get the fullnode client upload built")
	}
	if string(idx.data) != content {
		t.Errorf("uploaded data = %q, want %q", idx.data, content)
	}
	if len(idx.opts) != 1 || !reflect.DeepEqual(idx.opts[0], uploadOption(addr)) {
		t.Errorf("upload options = %+v, want exactly [%+v]", idx.opts, uploadOption(addr))
	}
	if !idx.closed {
		t.Error("indexer client not closed")
	}
}

func TestSDKUpload_Errors(t *testing.T) {
	priv, _ := testKey(t)
	boom := errors.New("boom")

	t.Run("empty data", func(t *testing.T) {
		r := &recordingSDK{idx: &fakeIndexer{}}
		_, err := r.sdk().upload(context.Background(), sealedIndexer, sealedRPC, nil, priv, logrus.New())
		if err == nil || !strings.HasPrefix(err.Error(), "prepare data: ") {
			t.Fatalf("err = %v", err)
		}
		if r.newWeb3 != 0 || r.newIndexer != 0 {
			t.Fatal("clients built for empty data")
		}
	})
	t.Run("fullnode client", func(t *testing.T) {
		r := &recordingSDK{web3Err: boom, idx: &fakeIndexer{}}
		_, err := r.sdk().upload(context.Background(), sealedIndexer, sealedRPC, []byte("x"), priv, logrus.New())
		if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "connect to fullnode: ") {
			t.Fatalf("err = %v", err)
		}
		if r.newIndexer != 0 {
			t.Fatal("indexer client built after the fullnode client failed")
		}
	})
	t.Run("indexer client", func(t *testing.T) {
		r := &recordingSDK{indexerErr: boom, idx: &fakeIndexer{}}
		_, err := r.sdk().upload(context.Background(), sealedIndexer, sealedRPC, []byte("x"), priv, logrus.New())
		if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "initialize indexer client: ") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("upload", func(t *testing.T) {
		r := &recordingSDK{idx: &fakeIndexer{err: boom}}
		_, err := r.sdk().upload(context.Background(), sealedIndexer, sealedRPC, []byte("x"), priv, logrus.New())
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

func TestUploadOption_MatchesCLIMapping(t *testing.T) {
	_, submitter := testKey(t)
	got := uploadOption(submitter)

	if got.Submitter != submitter {
		t.Errorf("Submitter = %s, want %s", got.Submitter, submitter)
	}
	if got.Fee != nil || got.Nonce != nil || got.MaxGasPrice != nil {
		t.Errorf("Fee/Nonce/MaxGasPrice = %v/%v/%v, want nil (CLI defaults)", got.Fee, got.Nonce, got.MaxGasPrice)
	}
	if got.NRetries != 0 || got.Step != 15 {
		t.Errorf("NRetries/Step = %d/%d, want 0/15", got.NRetries, got.Step)
	}
	if got.Tags == nil || len(got.Tags) != 0 {
		t.Errorf("Tags = %#v, want non-nil empty (CLI's decoded \"0x\")", got.Tags)
	}
	if got.EncryptionKey != nil || got.RecipientPubKey != nil {
		t.Error("encryption set; the CLI invocation never encrypted")
	}
	// The zero value is FileFinalized; the CLI without --finality-required
	// waits only for TransactionPacked.
	if got.FinalityRequired != transfer.TransactionPacked {
		t.Errorf("FinalityRequired = %v, want TransactionPacked", got.FinalityRequired)
	}
	if got.TaskSize != 10 || got.FragmentSize != 4*1024*1024*1024 || got.BatchSize != 10 {
		t.Errorf("TaskSize/FragmentSize/BatchSize = %d/%d/%d, want 10/4GiB/10", got.TaskSize, got.FragmentSize, got.BatchSize)
	}
	// What sealed's invocation pinned: --expected-replica 1 --skip-tx=true
	// --fast-mode=true --full-trusted=true --method random.
	if got.ExpectedReplica != 1 || !got.SkipTx || !got.FastMode || !got.FullTrusted || got.Method != "random" {
		t.Errorf("pinned fields = replica %d skipTx %v fast %v trusted %v method %q",
			got.ExpectedReplica, got.SkipTx, got.FastMode, got.FullTrusted, got.Method)
	}
}

func TestProviderOption_MatchesCLIDefaults(t *testing.T) {
	p := providerOption()
	if p.RetryCount != 5 || p.RetryInterval != 5*time.Second || p.RequestTimeout != 30*time.Second {
		t.Fatalf("provider option = %+v, want retry 5 / 5s / timeout 30s", p)
	}
	if p.MaxConnectionPerHost != 0 || p.Logger != nil || p.CircuitBreaker != nil {
		t.Fatalf("provider option = %+v, want the remaining fields unset, as the CLI leaves them", p)
	}
}

// cliSourceSHA256 pins the files of the pinned 0g-storage-client that
// define what `0g-storage-client upload --indexer` does: its flags and
// their defaults, the provider defaults, how it builds the fullnode client
// and the SDK calls it makes. upload.go mirrors them (uploadOption,
// providerOption, sdk.upload) and was checked against exactly these
// contents.
var cliSourceSHA256 = map[string]string{
	"cmd/upload.go":            "517b7b45d6e38abc25dc1102d05114bc607a3eb040a44d0007c1a745aa30385c",
	"cmd/root.go":              "ab82833a59c13a7cd613eaaa274e3b3f226db4786be33cb0b009f61757a06182",
	"common/blockchain/rpc.go": "c32e90b453829a607fc1369c3102d64effa78d2069fa778a32bfd9001d08fba1",
}

// TestCLISource_Unchanged turns "re-check upload.go when bumping the SDK"
// into a failing test: after a bump (sealed/go.mod) that changes any of the
// files above, re-check uploadOption, providerOption and sdk.upload against
// them, then record the new hashes.
func TestCLISource_Unchanged(t *testing.T) {
	checkSDKSources(t, cliSourceSHA256, "re-check uploadOption, providerOption and sdk.upload against it, then update cliSourceSHA256")
}

// submitPathSourceSHA256 pins the files of the pinned 0g-storage-client
// that the cap on its submit goroutines (admitUpload) was checked against:
// the submit goroutine that can block for good and its name
// (contract/contract.go), the size above which an upload starts one
// (transfer/uploader.go) and the attempts one upload makes
// (indexer/client.go).
var submitPathSourceSHA256 = map[string]string{
	"contract/contract.go": "30fb9934969787c2320565a4244756e7a0e67e12318bf92e3bad8f1792e7721c",
	"transfer/uploader.go": "5a84312cc89b188da41cf03d277e6071092af30d7eab0d515956668c6443a5c2",
	"indexer/client.go":    "8d306efda8e0f95fd7705e625c047a481883b74f713dfa6b2e17ece64d5a1009",
}

// TestSubmitPathSource_Unchanged: after an SDK bump that changes any of
// those files, re-check receiptPathAbove, submitsPerUpload and
// submitGoroutineFunc against them -- and drop the cap once the submit
// goroutine can no longer block for good -- then record the new hashes.
func TestSubmitPathSource_Unchanged(t *testing.T) {
	checkSDKSources(t, submitPathSourceSHA256, "re-check admitUpload's constants against it (drop the cap if the submit goroutine no longer blocks for good), then update submitPathSourceSHA256")
}

// checkSDKSources fails for each file of the pinned 0g-storage-client
// whose sha256 is not the one sums records; recheck says what to do.
func checkSDKSources(t *testing.T, sums map[string]string, recheck string) {
	t.Helper()
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
	for rel, want := range sums {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("the pinned SDK's %s changed (sha256 %s): %s", rel, got, recheck)
		}
	}
}

// TestInMemoryBlob_MatchesTheCLIsFile: the in-memory blob upload hands the
// SDK has the storage root and the submission that the CLI's file-backed
// one (core.Open) has, so the dataHash sealed records is the one the CLI
// produced. The sizes cover each upload path: the fast one (up to 256
// KiB), the parallel one (up to 2 MiB) and the receipt-waiting one.
func TestInMemoryBlob_MatchesTheCLIsFile(t *testing.T) {
	for _, n := range []int{1, 255, 256, 257, 4096, 256 * 1024, 256*1024 + 1, receiptPathAbove, receiptPathAbove + 7, 5*1024*1024 + 3} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			b := make([]byte, n)
			for i := range b {
				b[i] = byte(i*7 + n)
			}
			path := filepath.Join(t.TempDir(), "blob")
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := core.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			mem, err := core.NewDataInMemory(b)
			if err != nil {
				t.Fatal(err)
			}

			if file.Size() != mem.Size() || file.PaddedSize() != mem.PaddedSize() || file.NumChunks() != mem.NumChunks() || file.NumSegments() != mem.NumSegments() {
				t.Fatalf("file: size %d padded %d chunks %d segments %d; memory: %d %d %d %d",
					file.Size(), file.PaddedSize(), file.NumChunks(), file.NumSegments(),
					mem.Size(), mem.PaddedSize(), mem.NumChunks(), mem.NumSegments())
			}
			fileTree, err := core.MerkleTree(file)
			if err != nil {
				t.Fatal(err)
			}
			memTree, err := core.MerkleTree(mem)
			if err != nil {
				t.Fatal(err)
			}
			if fileTree.Root() != memTree.Root() {
				t.Fatalf("root: file %s, memory %s", fileTree.Root(), memTree.Root())
			}

			_, submitter := testKey(t)
			tags := uploadOption(submitter).Tags
			fileSub, err := core.NewFlow(file, tags).CreateSubmission(submitter)
			if err != nil {
				t.Fatal(err)
			}
			memSub, err := core.NewFlow(mem, tags).CreateSubmission(submitter)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fileSub, memSub) {
				t.Fatalf("submission: file %+v, memory %+v", fileSub, memSub)
			}
			if memSub.Root() != memTree.Root() {
				t.Fatalf("the submission's root %s is not the data's %s", memSub.Root(), memTree.Root())
			}
		})
	}
}

// ── Upload ─────────────────────────────────────────────────────────────────

// logSince returns sealed's log lines appended after the first n.
func logSince(n int) []string {
	return logger.Lines()[n:]
}

func TestUpload_ReturnsTheRootAndPassesTheBlob(t *testing.T) {
	priv, addr := testKey(t)
	root := common.HexToHash(testRoot)
	r := &recordingSDK{idx: &fakeIndexer{roots: []common.Hash{root}}}
	useSDK(t, r.sdk())

	blob := []byte("ciphertext bytes")
	got, err := Upload(context.Background(), blob, sealedIndexer, sealedRPC, priv)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if "0x"+hex.EncodeToString(got[:]) != testRoot {
		t.Fatalf("root = %x, want %s", got, testRoot)
	}
	if r.indexerURL != sealedIndexer || r.web3URL != sealedRPC {
		t.Fatalf("endpoints = indexer %q, fullnode %q", r.indexerURL, r.web3URL)
	}
	if string(r.idx.data) != string(blob) {
		t.Fatalf("SDK got %q, want the ciphertext", r.idx.data)
	}
	if len(r.idx.opts) != 1 || r.idx.opts[0].Submitter != addr {
		t.Fatalf("submitter = %+v, want %s", r.idx.opts, addr)
	}
}

// shortUploadTimeout sets perUploadTimeout to d for the rest of the test.
func shortUploadTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := perUploadTimeout
	perUploadTimeout = d
	t.Cleanup(func() { perUploadTimeout = prev })
}

// TestUpload_PerBlobDeadline: each call ends the SDK's context at
// perUploadTimeout even when the caller's has no deadline, and reports it
// as the deadline; the context itself carries no deadline (uploadContext).
func TestUpload_PerBlobDeadline(t *testing.T) {
	priv, _ := testKey(t)
	shortUploadTimeout(t, 200*time.Millisecond)
	var sdkDeadline atomic.Bool
	useSDK(t, (&recordingSDK{idx: &fakeIndexer{upload: func(ctx context.Context, _ core.IterableData) ([]common.Hash, error) {
		_, ok := ctx.Deadline()
		sdkDeadline.Store(ok)
		<-ctx.Done()
		return nil, fmt.Errorf("segment upload: %w", ctx.Err()) // as the SDK's own calls fail
	}}}).sdk())

	start := time.Now()
	_, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv)
	elapsed := time.Since(start)
	if err == nil || err.Error() != "0g-storage upload: context deadline exceeded" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the per-blob deadline", err)
	}
	if elapsed < perUploadTimeout || elapsed > perUploadTimeout+5*time.Second {
		t.Fatalf("Upload returned after %v, want about %v", elapsed, perUploadTimeout)
	}
	if sdkDeadline.Load() {
		t.Fatal("the SDK got a context with a deadline; the provider's per-request timeout would not apply")
	}
}

func TestUploadContext(t *testing.T) {
	type key struct{}
	boom := errors.New("boom")

	t.Run("no deadline, ends at the limit", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "v"), time.Hour)
		defer cancel()
		c, end := uploadContext(parent, 50*time.Millisecond)
		defer end()
		if _, ok := c.Deadline(); ok {
			t.Fatal("the upload context has a deadline")
		}
		if c.Value(key{}) != "v" {
			t.Fatal("the upload context lost the caller's values")
		}
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the upload context did not end at its limit")
		}
		if cause := context.Cause(c); cause != context.DeadlineExceeded {
			t.Fatalf("cause = %v, want context.DeadlineExceeded", cause)
		}
	})
	t.Run("ends with the caller", func(t *testing.T) {
		parent, cancel := context.WithCancelCause(context.Background())
		c, end := uploadContext(parent, time.Hour)
		defer end()
		cancel(boom)
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the upload context outlived the caller's")
		}
		if cause := context.Cause(c); cause != boom {
			t.Fatalf("cause = %v, want the caller's", cause)
		}
	})
	t.Run("caller already ended", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		<-parent.Done()
		c, end := uploadContext(parent, time.Hour)
		defer end()
		if c.Err() == nil || context.Cause(c) != context.DeadlineExceeded {
			t.Fatalf("err = %v, cause = %v; want it ended at once with the caller's cause", c.Err(), context.Cause(c))
		}
	})
	t.Run("end", func(t *testing.T) {
		c, end := uploadContext(context.Background(), time.Hour)
		end()
		if context.Cause(c) != context.Canceled {
			t.Fatalf("cause after end = %v, want context.Canceled", context.Cause(c))
		}
	})
}

// stallingRPCServer answers every JSON-RPC request with result "0x1",
// except the first, which it holds for stall (or until the client hangs
// up) before answering.
func stallingRPCServer(t *testing.T, stall time.Duration) *httptest.Server {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &q)
		if n.Add(1) == 1 {
			select {
			case <-time.After(stall):
			case <-r.Context().Done():
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": "0x1"})
	}))
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	return srv
}

// TestUpload_SDKRequestsKeepThePerRequestTimeout: a request the SDK makes
// on the context Upload hands it is cut off at the provider's request
// timeout, as it was under the CLI's context.Background(), even when the
// caller's context has a deadline -- not left to run on towards the
// upload's own limit. A context with a deadline shows the difference:
// there the stalled request runs its full length. The provider is the
// SDK's, with the CLI's option, its timeouts shortened.
func TestUpload_SDKRequestsKeepThePerRequestTimeout(t *testing.T) {
	const stall = 2 * time.Second
	opt := providerOption()
	opt.RequestTimeout = 300 * time.Millisecond
	opt.RetryInterval = 50 * time.Millisecond

	// request makes one call on ctx through a fresh provider against a
	// server whose first request stalls, and says how long it took.
	request := func(t *testing.T, ctx context.Context) time.Duration {
		p, err := providers.NewProviderWithOption(stallingRPCServer(t, stall).URL, opt)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		start := time.Now()
		var res string
		_ = p.CallContext(ctx, &res, "zgs_getStatus") // a retry after the timeout may or may not succeed
		return time.Since(start)
	}
	// throughUpload makes that call from inside Upload, on the SDK's context.
	throughUpload := func(t *testing.T, caller context.Context) time.Duration {
		priv, _ := testKey(t)
		var took time.Duration
		useSDK(t, (&recordingSDK{idx: &fakeIndexer{upload: func(ctx context.Context, _ core.IterableData) ([]common.Hash, error) {
			took = request(t, ctx)
			return []common.Hash{{1}}, nil
		}}}).sdk())
		if _, err := Upload(caller, []byte("ct"), sealedIndexer, sealedRPC, priv); err != nil {
			t.Fatalf("Upload: %v", err)
		}
		return took
	}

	withDeadline := func() context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		t.Cleanup(cancel)
		return ctx
	}
	for name, took := range map[string]func(t *testing.T) time.Duration{
		"Upload, caller without deadline": func(t *testing.T) time.Duration { return throughUpload(t, context.Background()) },
		"Upload, caller with deadline":    func(t *testing.T) time.Duration { return throughUpload(t, withDeadline()) },
		"the CLI's context.Background()":  func(t *testing.T) time.Duration { return request(t, context.Background()) },
	} {
		t.Run(name, func(t *testing.T) {
			if d := took(t); d >= stall/2 {
				t.Fatalf("the stalled request took %v; want it cut at the %v per-request timeout", d, opt.RequestTimeout)
			}
		})
	}
	t.Run("a context with a deadline", func(t *testing.T) {
		if d := request(t, withDeadline()); d < stall*9/10 {
			t.Fatalf("the stalled request took %v under a deadline; want the full %v (else this test cannot tell)", d, stall)
		}
	})
}

// TestUpload_ReturnsAtTheDeadline: an SDK call that ignores its context
// does not hold Upload past the deadline.
func TestUpload_ReturnsAtTheDeadline(t *testing.T) {
	priv, _ := testKey(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r := &recordingSDK{idx: &fakeIndexer{upload: func(context.Context, core.IterableData) ([]common.Hash, error) {
		<-release // ignores ctx, like the SDK's retry sleeps and receipt wait
		return []common.Hash{{1}}, nil
	}}}
	useSDK(t, r.sdk())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Upload(ctx, []byte("ct"), sealedIndexer, sealedRPC, priv)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Upload returned after %v; want it back at the deadline", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if err.Error() != "0g-storage upload: context deadline exceeded" {
		t.Fatalf("err = %q", err)
	}
}

// TestUpload_ErrorIsOneLineAndKeepsTheChain: the owner sees the last line of
// an upload error (summarizeError), so the SDK's cause must be on it.
func TestUpload_ErrorIsOneLineAndKeepsTheChain(t *testing.T) {
	priv, _ := testKey(t)
	cause := errors.New("Failed to submit log entry:\n  failed to send transaction: insufficient funds for gas * price + value")
	useSDK(t, (&recordingSDK{idx: &fakeIndexer{err: cause}}).sdk())

	_, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv)
	if err == nil {
		t.Fatal("Upload succeeded against a failing SDK")
	}
	want := "0g-storage upload: Failed to submit log entry: failed to send transaction: insufficient funds for gas * price + value"
	if err.Error() != want {
		t.Fatalf("err = %q\nwant  %q", err, want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("the error no longer wraps the SDK's")
	}
	assertNoKey(t, "error", err.Error())
}

// TestUpload_SDKLogOnlyOnFailure: the SDK's log lines for a call reach
// sealed's log, uncoloured, when the call fails, and are dropped when it
// succeeds.
func TestUpload_SDKLogOnlyOnFailure(t *testing.T) {
	priv, _ := testKey(t)
	for _, fail := range []bool{false, true} {
		probe := fmt.Sprintf("sdk-log-probe-%d-%v", time.Now().UnixNano(), fail)
		useSDK(t, (&recordingSDK{idx: &fakeIndexer{upload: func(context.Context, core.IterableData) ([]common.Hash, error) {
			logrus.WithField("root", "0xab").Info(probe)
			if fail {
				return nil, errors.New("segment upload failed")
			}
			return []common.Hash{{1}}, nil
		}}}).sdk())

		n := len(logger.Lines())
		_, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv)
		if (err != nil) != fail {
			t.Fatalf("fail=%v: err = %v", fail, err)
		}
		var found []string
		for _, line := range logSince(n) {
			assertNoKey(t, "sealed log", line)
			if strings.Contains(line, probe) {
				found = append(found, line)
			}
		}
		if !fail {
			if len(found) != 0 {
				t.Fatalf("a successful upload put the SDK's log in sealed's: %q", found)
			}
			continue
		}
		if len(found) != 1 {
			t.Fatalf("SDK log line in sealed's log %d times, want once: %q", len(found), logSince(n))
		}
		line := found[0]
		if !strings.Contains(line, "0g-storage: ") || !strings.Contains(line, "level=info") || strings.Contains(line, "\x1b[") {
			t.Fatalf("SDK log line = %q, want a plain-text logrus line prefixed 0g-storage:", line)
		}
	}
}

func TestUpload_RejectsSeveralRoots(t *testing.T) {
	priv, _ := testKey(t)
	useSDK(t, (&recordingSDK{idx: &fakeIndexer{roots: []common.Hash{{1}, {2}}}}).sdk())
	_, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv)
	if err == nil || err.Error() != "0g-storage upload: expected exactly one storage root, got 2" {
		t.Fatalf("err = %v", err)
	}
}

func TestUpload_NoSigner(t *testing.T) {
	r := &recordingSDK{idx: &fakeIndexer{roots: []common.Hash{{1}}}}
	useSDK(t, r.sdk())
	if _, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, nil); err == nil || err.Error() != "0g-storage upload: no signing key" {
		t.Fatalf("Upload without a signing key: err = %v", err)
	}
	if r.newWeb3 != 0 || r.idx.calls != 0 {
		t.Fatal("the SDK was called without a signing key")
	}
}

// TestUpload_RecoversSDKPanic: a panic in the SDK call fails the upload,
// not the process.
func TestUpload_RecoversSDKPanic(t *testing.T) {
	priv, _ := testKey(t)
	useSDK(t, (&recordingSDK{idx: &fakeIndexer{upload: func(context.Context, core.IterableData) ([]common.Hash, error) {
		panic("index out of bound")
	}}}).sdk())
	_, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv)
	if err == nil || err.Error() != "0g-storage upload: storage SDK panic: index out of bound" {
		t.Fatalf("err = %v", err)
	}
}

// TestUpload_FatalLogFailsTheUpload: logrus.Fatal in the SDK's calling
// goroutine fails the upload instead of exiting the process.
func TestUpload_FatalLogFailsTheUpload(t *testing.T) {
	priv, _ := testKey(t)
	useSDK(t, (&recordingSDK{idx: &fakeIndexer{upload: func(context.Context, core.IterableData) ([]common.Hash, error) {
		logrus.WithField("url", "http://node").Fatal("Failed to create zgs client")
		return []common.Hash{{1}}, nil
	}}}).sdk())
	_, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv)
	if err == nil || !strings.Contains(err.Error(), "storage SDK requested process exit (status 1)") {
		t.Fatalf("err = %v", err)
	}
}

// TestUpload_WritesNoFile: the blob goes to the SDK from memory; Upload
// creates no temp file.
func TestUpload_WritesNoFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	priv, _ := testKey(t)
	useSDK(t, (&recordingSDK{idx: &fakeIndexer{roots: []common.Hash{{1}}}}).sdk())
	if _, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Fatalf("Upload left %d entries in TMPDIR", len(entries))
	}
}

// TestUpload_AbandonedCallKeepsItsOwnCopy: an SDK call that outlives
// Upload (abandoned at the deadline) reads its own copy of the blob, not
// the caller's buffer, which the caller is free to reuse.
func TestUpload_AbandonedCallKeepsItsOwnCopy(t *testing.T) {
	priv, _ := testKey(t)
	release := make(chan struct{})
	readBack := make(chan string, 1)
	useSDK(t, (&recordingSDK{idx: &fakeIndexer{upload: func(_ context.Context, data core.IterableData) ([]common.Hash, error) {
		<-release
		b := make([]byte, data.Size())
		_, _ = data.Read(b, 0)
		readBack <- string(b)
		return nil, errors.New("late")
	}}}).sdk())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	blob := []byte("ct")
	if _, err := Upload(ctx, blob, sealedIndexer, sealedRPC, priv); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	blob[0] = 'X'
	close(release)
	select {
	case got := <-readBack:
		if got != "ct" {
			t.Fatalf("the abandoned call read %q, want its own copy %q", got, "ct")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned call never finished")
	}
}

// signWith signs a throwaway transaction with the signer the SDK was
// handed for addr (through the fullnode client's signer manager, the way
// the SDK's contract calls sign).
func signWith(w3 *web3go.Client, addr common.Address) error {
	_, err := signRaw(w3, addr)
	return err
}

// signRaw is signWith returning the signed transaction's encoding.
func signRaw(w3 *web3go.Client, addr common.Address) ([]byte, error) {
	sm, err := w3.GetSignerManager()
	if err != nil {
		return nil, err
	}
	s, err := sm.Get(addr)
	if err != nil {
		return nil, err
	}
	tx := ethtypes.NewTx(&ethtypes.LegacyTx{Nonce: 1, GasPrice: big.NewInt(1), Gas: 21000})
	signed, err := s.SignTransaction(tx, big.NewInt(16602))
	if err != nil {
		return nil, err
	}
	return signed.MarshalBinary()
}

// TestUpload_AbandonedCallCannotSign: an SDK call Upload gave up on at the
// deadline can no longer sign a new transaction after Upload has returned;
// while the upload is live, signing works.
func TestUpload_AbandonedCallCannotSign(t *testing.T) {
	priv, addr := testKey(t)
	release := make(chan struct{})
	signed := make(chan error, 2)
	idx := &fakeIndexer{}
	idx.upload = func(context.Context, core.IterableData) ([]common.Hash, error) {
		signed <- signWith(idx.w3, addr)
		<-release
		signed <- signWith(idx.w3, addr)
		return nil, errors.New("late")
	}
	useSDK(t, (&recordingSDK{idx: idx}).sdk())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := Upload(ctx, []byte("ct"), sealedIndexer, sealedRPC, priv); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	if err := <-signed; err != nil {
		t.Fatalf("signing during the upload: %v", err)
	}
	close(release)
	select {
	case err := <-signed:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("signing after Upload gave up = %v, want a refusal (context.DeadlineExceeded)", err)
		}
		assertNoKey(t, "signing error", err.Error())
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned call never tried to sign")
	}
}

// TestUpload_SignerEndsWithTheCall: a signer the SDK kept hold of is
// useless once Upload has returned, even after a successful upload.
func TestUpload_SignerEndsWithTheCall(t *testing.T) {
	priv, addr := testKey(t)
	r := &recordingSDK{idx: &fakeIndexer{roots: []common.Hash{{1}}}}
	useSDK(t, r.sdk())
	if _, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if err := signWith(r.web3, addr); !errors.Is(err, context.Canceled) {
		t.Fatalf("signing after Upload returned = %v, want a refusal (context.Canceled)", err)
	}
	var msgErr error
	if sm, err := r.web3.GetSignerManager(); err == nil {
		_, msgErr = sm.List()[0].SignMessage([]byte("hello"))
	}
	if !errors.Is(msgErr, context.Canceled) {
		t.Fatalf("message signing after Upload returned = %v, want a refusal", msgErr)
	}
}

// TestUpload_AbandonedCallCannotSend: a transaction the SDK signed while
// the upload was live is not sent once Upload has given up on it, not even
// by the provider's retries: the first attempt, made while the upload is
// live, fails at the node, and the retry, after the deadline, is refused.
// While the upload is live the retry goes out, which shows the check runs
// inside the provider's retry loop.
func TestUpload_AbandonedCallCannotSend(t *testing.T) {
	priv, addr := testKey(t)
	for _, abandoned := range []bool{false, true} {
		t.Run(fmt.Sprintf("abandoned=%v", abandoned), func(t *testing.T) {
			// The node fails the first send (HTTP 503, which the provider
			// retries) and accepts the next.
			var sends atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var q struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
				}
				_ = json.Unmarshal(body, &q)
				if q.Method == "eth_sendRawTransaction" && sends.Add(1) == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": common.Hash{1}})
			}))
			defer srv.Close()

			sent := make(chan error, 1)
			idx := &fakeIndexer{}
			idx.upload = func(context.Context, core.IterableData) ([]common.Hash, error) {
				raw, err := signRaw(idx.w3, addr)
				if err == nil {
					_, err = idx.w3.Eth.SendRawTransaction(raw)
				}
				sent <- err
				return []common.Hash{{1}}, err
			}
			r := &recordingSDK{idx: idx, web3Tweak: func(o *web3go.ClientOption) { o.RetryInterval = 300 * time.Millisecond }}
			useSDK(t, r.sdk())

			ctx := context.Background()
			if abandoned {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			_, err := Upload(ctx, []byte("ct"), sealedIndexer, srv.URL, priv)
			if abandoned != errors.Is(err, context.DeadlineExceeded) || !abandoned && err != nil {
				t.Fatalf("Upload: %v", err)
			}
			var sendErr error
			select {
			case sendErr = <-sent:
			case <-time.After(10 * time.Second):
				t.Fatal("the send never finished")
			}
			if !abandoned {
				if sendErr != nil || sends.Load() != 2 {
					t.Fatalf("live upload: send = %v after %d attempts at the node, want it through on the retry", sendErr, sends.Load())
				}
				return
			}
			if !errors.Is(sendErr, context.DeadlineExceeded) || !strings.Contains(sendErr.Error(), "upload ended before the transaction was sent") {
				t.Fatalf("send after Upload gave up = %v, want a refusal", sendErr)
			}
			assertNoKey(t, "send error", sendErr.Error())
			if n := sends.Load(); n != 1 {
				t.Fatalf("the node got %d sends, want only the one made while the upload was live", n)
			}
		})
	}
}

// TestRefuseSendsAfter: once its context has ended, a provider refuses
// single and batched sends, with the context's cause, and still makes
// every other call.
func TestRefuseSendsAfter(t *testing.T) {
	srv, calls := jsonRPCErrorServer(t)
	p, err := providers.NewProviderWithOption(srv.URL, providers.Option{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, end := context.WithCancelCause(context.Background())
	refuseSendsAfter(ctx, p)
	bg := context.Background()
	batch := func(methods ...string) []rpc.BatchElem {
		var b []rpc.BatchElem
		for _, m := range methods {
			b = append(b, rpc.BatchElem{Method: m, Args: []any{"0x00"}, Result: new(string)})
		}
		return b
	}

	if err := p.BatchCallContext(bg, batch("eth_chainId", "eth_sendRawTransaction")); err != nil {
		t.Fatalf("batch while live: %v", err)
	}
	if err := p.CallContext(bg, new(string), "eth_sendRawTransaction", "0x00"); !rpcJSONError(err) {
		t.Fatalf("send while live = %v, want the node's answer", err)
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("the node got %d calls while live, want 3", n)
	}

	end(context.DeadlineExceeded)
	for _, m := range []string{"eth_sendRawTransaction", "eth_sendTransaction"} {
		if err := p.CallContext(bg, new(string), m, "0x00"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s after the end = %v, want a refusal", m, err)
		}
	}
	if err := p.BatchCallContext(bg, batch("eth_chainId", "eth_sendRawTransaction")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("batched send after the end = %v, want a refusal", err)
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("the node got %d calls, want no new ones from refused sends", n)
	}
	if err := p.BatchCallContext(bg, batch("eth_chainId")); err != nil {
		t.Fatalf("batch without a send after the end: %v", err)
	}
	if err := p.CallContext(bg, new(string), "eth_chainId"); !rpcJSONError(err) {
		t.Fatalf("read after the end = %v, want the node's answer", err)
	}
	if n := calls.Load(); n != 5 {
		t.Fatalf("the node got %d calls, want the two reads after the end too", n)
	}
}

// rpcJSONError reports whether err is the node's JSON-RPC error (the
// test server answers every call with one).
func rpcJSONError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "method not found")
}

// TestUpload_FailureLogLeavesOutOtherCalls: a failed call's log report
// keeps its own logger's lines and leaves out what another call's logger
// wrote meanwhile -- here an earlier call abandoned at its deadline that
// is still winding down.
func TestUpload_FailureLogLeavesOutOtherCalls(t *testing.T) {
	priv, _ := testKey(t)
	tag := fmt.Sprint(time.Now().UnixNano())
	startedA, releaseA, doneA := make(chan struct{}), make(chan struct{}), make(chan struct{})
	// Each call gets its own stand-in indexer client, logging through the
	// logger that call handed the SDK.
	var calls atomic.Int32
	useSDK(t, sdk{
		newWeb3: web3go.NewClientWithOption,
		newIndexer: func(_ string, opt indexer.IndexerClientOption) (splitUploader, error) {
			log, first := opt.LogOption.Logger, calls.Add(1) == 1
			return &fakeIndexer{upload: func(context.Context, core.IterableData) ([]common.Hash, error) {
				if first {
					log.Info("A-own-" + tag)
					close(startedA)
					<-releaseA
					log.Info("A-late-" + tag)
					close(doneA)
					return nil, errors.New("late")
				}
				close(releaseA)
				<-doneA
				log.Info("B-own-" + tag)
				return nil, errors.New("segment upload failed")
			}}, nil
		},
	})

	n0 := len(logger.Lines())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Upload(ctx, []byte("ct"), sealedIndexer, sealedRPC, priv); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Upload: %v, want the deadline", err)
	}
	<-startedA
	n1 := len(logger.Lines())
	if _, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv); err == nil {
		t.Fatal("second Upload succeeded")
	}
	first := strings.Join(logger.Lines()[n0:n1], "\n")
	second := strings.Join(logSince(n1), "\n")
	if !strings.Contains(first, "A-own-"+tag) {
		t.Fatalf("the abandoned call's report lacks its own line:\n%s", first)
	}
	if !strings.Contains(second, "B-own-"+tag) {
		t.Fatalf("the failed call's report lacks its own line:\n%s", second)
	}
	if strings.Contains(second, "A-late-"+tag) {
		t.Fatalf("the failed call's report carries the abandoned call's line:\n%s", second)
	}
}

func TestLogRing(t *testing.T) {
	r := &logRing{max: 3}
	w := r.writer(0)
	m0 := r.mark()
	if got := r.since(m0, 1); got != nil {
		t.Fatalf("since on an empty ring = %q", got)
	}
	fmt.Fprint(w, "a\n")
	mA := r.mark()
	fmt.Fprint(w, "b\nc\n")
	m1 := r.mark()
	if got := r.since(m0, 1); strings.Join(got, "|") != "a|b|c" {
		t.Fatalf("since(m0) = %q", got)
	}
	fmt.Fprint(w, "d\n")
	fmt.Fprint(w, strings.Repeat("x", sdkLogLineMax+10)+"\n")
	if got := r.since(m1, 1); len(got) != 2 || got[0] != "d" || !strings.HasSuffix(got[1], " ...(truncated)") || len(got[1]) != sdkLogLineMax+len(" ...(truncated)") {
		t.Fatalf("since(m1) = %q", got)
	}
	long := strings.Repeat("x", sdkLogLineMax) + " ...(truncated)"
	if got := r.since(m0, 1); strings.Join(got, "|") != "(2 earlier lines dropped)|c|d|"+long {
		t.Fatalf("since(m0) after overflow = %q", got)
	}
	if got := r.since(mA, 1); strings.Join(got, "|") != "(1 earlier lines dropped)|c|d|"+long {
		t.Fatalf("since(mA) after overflow = %q", got)
	}
}

// TestLogRing_ByCall: since keeps the asking call's lines and the
// unattributed ones (0), and leaves out other calls'.
func TestLogRing_ByCall(t *testing.T) {
	r := &logRing{max: 10}
	m := r.mark()
	fmt.Fprint(r.writer(1), "one\n")
	fmt.Fprint(r.writer(0), "shared\n")
	fmt.Fprint(r.writer(2), "two-a\ntwo-b\n")
	if got := strings.Join(r.since(m, 1), "|"); got != "one|shared" {
		t.Fatalf("since(m, 1) = %q", got)
	}
	if got := strings.Join(r.since(m, 2), "|"); got != "shared|two-a|two-b" {
		t.Fatalf("since(m, 2) = %q", got)
	}
	if got := r.since(r.mark(), 1); got != nil {
		t.Fatalf("since(now) = %q", got)
	}
}

// ── The SDK's blocked submit goroutines ────────────────────────────────────

// TestUpload_RefusesLargeBlobsAtTheSubmitGoroutineCap: a blob over 2 MiB
// is not uploaded when that upload's submissions could take the SDK's live
// submit goroutines past the cap, and the SDK is not called; up to the
// cap, and for a blob of 2 MiB or less whatever the count, the upload runs.
func TestUpload_RefusesLargeBlobsAtTheSubmitGoroutineCap(t *testing.T) {
	priv, _ := testKey(t)
	for _, tc := range []struct {
		size, live int
		refused    bool
	}{
		{receiptPathAbove, maxSubmitGoroutines + 5, false},
		{receiptPathAbove + 1, maxSubmitGoroutines - submitsPerUpload, false},
		{receiptPathAbove + 1, maxSubmitGoroutines - submitsPerUpload + 1, true},
		{receiptPathAbove + 1, maxSubmitGoroutines, true},
	} {
		t.Run(fmt.Sprintf("size=%d,live=%d", tc.size, tc.live), func(t *testing.T) {
			prev := submitGoroutines
			submitGoroutines = func() int { return tc.live }
			t.Cleanup(func() { submitGoroutines = prev })
			r := &recordingSDK{idx: &fakeIndexer{roots: []common.Hash{{1}}}}
			useSDK(t, r.sdk())

			_, err := Upload(context.Background(), make([]byte, tc.size), sealedIndexer, sealedRPC, priv)
			if !tc.refused {
				if err != nil || r.idx.calls != 1 {
					t.Fatalf("Upload = %v after %d SDK calls, want it through", err, r.idx.calls)
				}
				return
			}
			want := fmt.Sprintf("0g-storage upload: refused a %d-byte blob: the storage SDK holds %d submit goroutines, and an upload over 2 MiB could take it past %d (those of failed submissions end only when sealed restarts)",
				tc.size, tc.live, maxSubmitGoroutines)
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v\nwant  %s", err, want)
			}
			if r.newWeb3 != 0 || r.newIndexer != 0 || r.idx.calls != 0 {
				t.Fatal("the SDK was called for a refused upload")
			}
		})
	}
}

// revertingNode is a fullnode stand-in that accepts every transaction and
// then reports it reverted. It counts the transactions sent to it.
func revertingNode(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var sends atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &q)
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x40da"
		case "eth_getTransactionCount":
			result = "0x0"
		case "eth_gasPrice":
			result = "0x3b9aca00"
		case "eth_getCode":
			result = "0x6000"
		case "eth_estimateGas":
			result = "0x5208"
		case "eth_sendRawTransaction":
			sends.Add(1)
			result = "0x" + strings.Repeat("ab", 32)
		case "eth_getTransactionReceipt":
			var hash string
			if len(q.Params) > 0 {
				_ = json.Unmarshal(q.Params[0], &hash)
			}
			result = map[string]any{
				"status": "0x0", "txExecErrorMsg": "reverted", "transactionHash": hash,
				"blockNumber": "0x1", "blockHash": "0x" + strings.Repeat("cd", 32),
				"logs": []any{}, "gasUsed": "0x5208", "cumulativeGasUsed": "0x5208",
				"transactionIndex": "0x0", "effectiveGasPrice": "0x1",
				"from": "0x" + strings.Repeat("00", 20), "to": "0x" + strings.Repeat("00", 19) + "01",
				"logsBloom": "0x" + strings.Repeat("00", 256),
			}
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	return srv, &sends
}

// receiptPathSubmit submits data the way the pinned SDK does for a blob
// over 2 MiB that is not on chain yet (transfer.Uploader.SubmitLogEntry,
// waiting for the receipt): through contract.TransactWithGasAdjustment,
// with the retry option upload's options make, on the fullnode client w3.
func receiptPathSubmit(ctx context.Context, w3 *web3go.Client, data core.IterableData, opt transfer.UploadOption) error {
	flow, err := contract.NewFlowContract(common.HexToAddress("0x0000000000000000000000000000000000000001"), w3)
	if err != nil {
		return err
	}
	submission, err := core.NewFlow(data, opt.Tags).CreateSubmission(opt.Submitter)
	if err != nil {
		return err
	}
	opts, err := flow.CreateTransactOpts(ctx)
	if err != nil {
		return err
	}
	opts.Value = big.NewInt(0) // the SDK pays the market's fee; the stand-in node takes anything
	retry := &contract.TxRetryOption{MaxGasPrice: opt.MaxGasPrice, MaxNonGasRetries: opt.NRetries, Step: opt.Step}
	_, err = contract.TransactWithGasAdjustment(flow, "submit", opts, retry, opt.OnSubmitted, *submission)
	return err
}

// blockedSubmitGoroutines counts the goroutines blocked on a channel send
// in submitGoroutineFunc, from the runtime's own goroutine dump.
func blockedSubmitGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.HasPrefix(g, "goroutine ") && strings.Contains(g, " [chan send") && strings.Contains(g, "\n"+submitGoroutineFunc+"(") {
			count++
		}
	}
	return count
}

// TestUpload_BlockedSubmitGoroutinesStayBounded: a reverted submission of
// a blob over 2 MiB, made by the pinned SDK's own submit function through
// the fullnode client upload builds, leaves the SDK's submit goroutine
// blocked for good once its 30s sleep is over -- the defect the cap
// exists for. That goroutine counts towards the cap from the start, and
// once the cap is reached further blobs over 2 MiB are refused without
// reaching the SDK or the node, so the goroutines stop growing; blobs of
// 2 MiB or less still go through. If the goroutine no longer blocks, the
// SDK has been fixed: drop the cap.
func TestUpload_BlockedSubmitGoroutinesStayBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the SDK's 30s submit sleep")
	}
	priv, addr := testKey(t)
	node, sends := revertingNode(t)
	idx := &fakeIndexer{}
	idx.upload = func(ctx context.Context, data core.IterableData) ([]common.Hash, error) {
		if data.Size() <= receiptPathAbove {
			return []common.Hash{{1}}, nil // the SDK's paths that do not wait for a receipt
		}
		return nil, receiptPathSubmit(ctx, idx.w3, data, uploadOption(addr))
	}
	useSDK(t, (&recordingSDK{idx: idx}).sdk())
	live, blocked := countSubmitGoroutines(), blockedSubmitGoroutines()
	prevMax := maxSubmitGoroutines
	maxSubmitGoroutines = live + submitsPerUpload // room for one more upload over 2 MiB
	t.Cleanup(func() { maxSubmitGoroutines = prevMax })
	large := make([]byte, receiptPathAbove+1)

	_, err := Upload(context.Background(), large, sealedIndexer, node.URL, priv)
	if err == nil || !strings.HasSuffix(err.Error(), "Transaction execution failed, reverted") || sends.Load() != 1 {
		t.Fatalf("Upload = %v after %d sends, want the reverted submission", err, sends.Load())
	}
	if n := countSubmitGoroutines(); n != live+1 {
		t.Fatalf("live submit goroutines = %d after the submission, want %d", n, live+1)
	}
	if _, err := Upload(context.Background(), large, sealedIndexer, node.URL, priv); err == nil || !strings.Contains(err.Error(), "refused a 2097153-byte blob") {
		t.Fatalf("Upload at the cap = %v, want it refused", err)
	}
	if idx.calls != 1 || sends.Load() != 1 {
		t.Fatalf("a refused upload reached the SDK (%d calls) or the node (%d sends)", idx.calls, sends.Load())
	}
	if _, err := Upload(context.Background(), make([]byte, receiptPathAbove), sealedIndexer, node.URL, priv); err != nil {
		t.Fatalf("Upload of 2 MiB at the cap: %v", err)
	}

	deadline := time.Now().Add(45 * time.Second)
	for blockedSubmitGoroutines() <= blocked {
		if time.Now().After(deadline) {
			t.Fatal("the SDK's submit goroutine did not block after its 30s sleep; if the pinned SDK no longer leaves it behind, drop the cap (admitUpload)")
		}
		time.Sleep(500 * time.Millisecond)
	}
	if n := countSubmitGoroutines(); n != live+1 {
		t.Fatalf("live submit goroutines = %d with one blocked, want %d", n, live+1)
	}
	before := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		if _, err := Upload(context.Background(), large, sealedIndexer, node.URL, priv); err == nil {
			t.Fatal("Upload over the cap went through")
		}
	}
	if after := runtime.NumGoroutine(); after > before || countSubmitGoroutines() != live+1 || sends.Load() != 1 {
		t.Fatalf("after refused uploads: goroutines %d -> %d, submit goroutines %d, sends %d", before, after, countSubmitGoroutines(), sends.Load())
	}
}
