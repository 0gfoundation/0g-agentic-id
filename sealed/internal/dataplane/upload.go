package dataplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	rpc "github.com/openweb3/go-rpc-provider"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/openweb3/web3go"
	"github.com/openweb3/web3go/interfaces"
	"github.com/openweb3/web3go/signers"
	web3types "github.com/openweb3/web3go/types"
	"github.com/sirupsen/logrus"

	"seal-verify/internal/logger"
)

// Uploads run in-process through the 0g-storage-client Go SDK (pinned in
// sealed/go.mod), with the semantics of the `0g-storage-client upload
// --indexer` invocation sealed used to run: the SDK calls of that CLI path
// (cmd/upload.go at the pinned version), its defaults for every parameter
// sealed never set, and these pinned values:
//
//	expected replica 1     small payload, single replica is fine
//	skip tx                skip flow tx submission if already submitted
//	fast mode              small-file fast path (CLI default)
//	full trusted           use trusted nodes (CLI default)
//	method random          avoid shard.Select empty-method bug
//
// The signing key never leaves this process: the SDK's signer is built from
// the parsed key the caller already holds, so no child process, argument
// list, environment, descriptor or file carries it. TestSDKUpload_WiresTheCLIPath
// pins what upload hands the SDK, and TestCLISource_Unchanged fails when an
// SDK bump changes the CLI files this was checked against.
//
// Like the CLI, which ran on context.Background(), the SDK gets a context
// without a deadline (uploadContext), so the provider's request timeout
// applies; Upload's 90s cap ends that context instead.

// Fixed upload parameters, all equal to the `0g-storage-client upload`
// defaults (cmd/upload.go, cmd/root.go) that sealed never overrode.
const (
	cliTaskSize       = 10
	cliFragmentSize   = int64(4) * 1024 * 1024 * 1024
	cliBatchSize      = 10
	cliGasPriceStep   = 15
	cliRPCRetryCount  = 5
	cliRPCRetryPeriod = 5 * time.Second
	cliRPCTimeout     = 30 * time.Second
)

// Parameters sealed pins on every upload (see the list above).
const (
	uploadExpectedReplica = 1
	uploadSkipTx          = true
	uploadFastMode        = true
	uploadFullTrusted     = true
	uploadMethod          = "random"
)

// perUploadTimeout bounds a single blob's upload. 90s is generous for
// testnet conditions (typical successful uploads land in ~10s) while still
// tight enough to surface a genuinely hung upload. The cap lives here — not
// on the surrounding Apply — so the cost of one slow blob doesn't eat the
// budget of the other entries in the same manifest. A variable only so
// tests can shorten it.
var perUploadTimeout = 90 * time.Second

// providerOption mirrors the CLI's RPC defaults (cmd/root.go). The provider
// applies RequestTimeout only to calls whose context has no deadline of its
// own (go-rpc-provider's TimeoutMiddleware), which is why the context the
// SDK gets has none (uploadContext).
func providerOption() providers.Option {
	return providers.Option{
		RetryCount:     cliRPCRetryCount,
		RetryInterval:  cliRPCRetryPeriod,
		RequestTimeout: cliRPCTimeout,
	}
}

// uploadOption is the SDK option `0g-storage-client upload` builds for the
// flags sealed used to pass it.
func uploadOption(submitter common.Address) transfer.UploadOption {
	return transfer.UploadOption{
		TransactionOption: transfer.TransactionOption{
			Submitter: submitter,
			Step:      cliGasPriceStep,
		},
		// Non-nil and empty, like the CLI's decoded "0x" default: nil and
		// empty tags encode differently.
		Tags:             []byte{},
		FinalityRequired: transfer.TransactionPacked,
		TaskSize:         cliTaskSize,
		ExpectedReplica:  uploadExpectedReplica,
		SkipTx:           uploadSkipTx,
		FastMode:         uploadFastMode,
		Method:           uploadMethod,
		FullTrusted:      uploadFullTrusted,
		FragmentSize:     cliFragmentSize,
		BatchSize:        cliBatchSize,
	}
}

// sdk holds the 0g-storage-client SDK client constructors upload uses.
// storageSDK has the SDK's own; tests substitute recorders, so the wiring
// runs without a network.
type sdk struct {
	newWeb3    func(url string, opt web3go.ClientOption) (*web3go.Client, error)
	newIndexer func(url string, opt indexer.IndexerClientOption) (splitUploader, error)
}

// splitUploader is the part of *indexer.Client that upload calls.
type splitUploader interface {
	SplitableUpload(ctx context.Context, w3Client *web3go.Client, data core.IterableData, option ...transfer.UploadOption) ([]common.Hash, []common.Hash, error)
	Close()
}

var storageSDK = sdk{
	newWeb3: web3go.NewClientWithOption,
	newIndexer: func(url string, opt indexer.IndexerClientOption) (splitUploader, error) {
		c, err := indexer.NewClient(url, opt)
		if err != nil {
			return nil, err
		}
		return c, nil
	},
}

// upload performs the SDK calls of the CLI's --indexer upload path for one
// in-memory blob and returns the storage roots. The signer wraps priv
// itself; no copy of the key in any other form is made. Once ctx has ended,
// the signer refuses to sign and the fullnode client refuses to send a
// transaction. log is the logger the SDK's clients get (the CLI passes
// logrus's package-level one).
func (s sdk) upload(ctx context.Context, indexerURL, rpcURL string, data []byte, priv *ecdsa.PrivateKey, log *logrus.Logger) ([]common.Hash, error) {
	// The CLI opens a file (core.Open); the in-memory form yields the same
	// chunks, so the same root and submission, without a temp file
	// (TestInMemoryBlob_MatchesTheCLIsFile).
	blob, err := core.NewDataInMemory(data)
	if err != nil {
		return nil, fmt.Errorf("prepare data: %w", err)
	}

	signer := boundSigner{Signer: signers.NewPrivateKeySigner(priv), ctx: ctx}
	clientOpt := web3go.ClientOption{Option: providerOption()}
	clientOpt.WithSignerManager(signers.NewSignerManager([]interfaces.Signer{signer}))
	w3client, err := s.newWeb3(rpcURL, clientOpt)
	if err != nil {
		return nil, fmt.Errorf("connect to fullnode: %w", err)
	}
	defer w3client.Close()
	refuseSendsAfter(ctx, w3client.Provider())

	indexerClient, err := s.newIndexer(indexerURL, indexer.IndexerClientOption{
		ProviderOption: providerOption(),
		LogOption:      zg_common.LogOption{Logger: log},
		Routines:       runtime.GOMAXPROCS(0),
		Contract:       &transfer.ContractAddress{},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize indexer client: %w", err)
	}
	defer indexerClient.Close()

	_, roots, err := indexerClient.SplitableUpload(ctx, w3client, blob, uploadOption(signer.Address()))
	if err != nil {
		return nil, err
	}
	return roots, nil
}

// boundSigner signs for one upload, and only while that upload's context
// is live. Every transaction the SDK sends is signed through it (web3go's
// signer manager), but the SDK's contract backend ignores contexts, so an
// upload abandoned at its deadline (Upload) could otherwise still sign a
// new storage transaction afterwards.
type boundSigner struct {
	interfaces.Signer
	ctx context.Context
}

func (s boundSigner) SignTransaction(tx *web3types.Transaction, chainID *big.Int) (*web3types.Transaction, error) {
	if s.ctx.Err() != nil {
		return nil, fmt.Errorf("upload ended before the transaction was signed: %w", context.Cause(s.ctx))
	}
	return s.Signer.SignTransaction(tx, chainID)
}

func (s boundSigner) SignMessage(text []byte) ([]byte, error) {
	if s.ctx.Err() != nil {
		return nil, fmt.Errorf("upload ended before the message was signed: %w", context.Cause(s.ctx))
	}
	return s.Signer.SignMessage(text)
}

// sendMethods are the JSON-RPC methods that hand a transaction to the node.
var sendMethods = map[string]bool{
	"eth_sendRawTransaction": true,
	"eth_sendTransaction":    true,
}

// refuseSendsAfter makes p, the fullnode client's provider, refuse to send
// a transaction once ctx has ended. A transaction signed while the upload
// was live is otherwise still sent after it: the SDK's contract backend
// sends without a context, and the provider retries a failed send (up to 5
// times, 5s apart). The hook is added last, after the timeout, retry and
// signing layers the client was built with, and the provider runs hooks in
// the order they were added, so it runs on every attempt, retries included.
// A request already on the wire when ctx ends can still reach the node.
func refuseSendsAfter(ctx context.Context, p *providers.MiddlewarableProvider) {
	refused := func() error {
		if ctx.Err() == nil {
			return nil
		}
		return fmt.Errorf("upload ended before the transaction was sent: %w", context.Cause(ctx))
	}
	p.HookCallContext(func(next providers.CallContextFunc) providers.CallContextFunc {
		return func(c context.Context, result interface{}, method string, args ...interface{}) error {
			if sendMethods[method] {
				if err := refused(); err != nil {
					return err
				}
			}
			return next(c, result, method, args...)
		}
	})
	p.HookBatchCallContext(func(next providers.BatchCallContextFunc) providers.BatchCallContextFunc {
		return func(c context.Context, b []rpc.BatchElem) error {
			for _, e := range b {
				if sendMethods[e.Method] {
					if err := refused(); err != nil {
						return err
					}
				}
			}
			return next(c, b)
		}
	})
}

// Upload pushes ciphertext to 0g-storage and returns the storage root
// hash. The root is what gets recorded as IntelligentData.dataHash on
// chain. signer is the agent_seal key: it signs the storage submission tx
// and pays gas. The upload runs in this process (see the top of this file);
// no child process is started and the key is never written anywhere.
//
// Each call is capped at perUploadTimeout, on top of ctx. The SDK does not
// stop at once when its context ends -- its RPC retries sleep between
// attempts, its contract backend ignores contexts, and it waits for a
// broadcast transaction's receipt on a context of its own -- so Upload
// returns at the deadline without waiting for it, and the abandoned call
// winds down by itself, with one exception: a submission of a blob over
// 2 MiB that reverts, or whose receipt query fails, leaves a goroutine of
// the SDK's blocked for good, abandoned call or not, which is why Upload
// caps how many it lets pile up (admitUpload). From then on its signer (boundSigner) refuses to sign and
// its fullnode client (refuseSendsAfter) refuses to send a transaction,
// provider retries included; a send already on the wire at the deadline
// can still reach the node, as it could when the CLI was killed there.
//
// The SDK shares sealed's process, so an upload is not isolated the way a
// CLI run was. A panic in the goroutine that calls the SDK (a fatal log
// there included, which configureLogger turns into one) is recovered by
// runBounded and returned as an error. A panic in a goroutine the SDK
// starts itself, which the SDK does not recover, or memory exhausted
// during an upload, ends sealed (PID 1) and with it the container and the
// agent. That is the trade accepted to keep the key in this process
// (QUIRKS.md).
//
// Errors read "0g-storage upload: <cause>" on a single line, so the summary
// sealed reports to the owner (summarizeError in sealed/status.go) is the
// whole cause. On failure, the SDK's log lines for the call are written to
// sealed's log first; on success they are dropped. Lines the SDK logs
// through logrus's package-level logger cannot be told apart by call, so a
// failed call's lines can include ones from an earlier call that was
// abandoned at its deadline and is still winding down (see sdkLog).
func Upload(
	ctx context.Context,
	ciphertext []byte,
	indexerURL string,
	rpcURL string,
	signer *ecdsa.PrivateKey,
) ([32]byte, error) {
	if signer == nil {
		return [32]byte{}, errors.New("0g-storage upload: no signing key")
	}
	if err := admitUpload(len(ciphertext)); err != nil {
		return [32]byte{}, fmt.Errorf("0g-storage upload: %w", err)
	}
	// Ends with the caller's ctx, so an Apply-level cancel still
	// propagates, but caps this blob at perUploadTimeout even when the
	// parent context is effectively unbounded (uploader.Apply runs without
	// a top-level timeout since sealed/main.go's drift loop).
	uploadCtx, end := uploadContext(ctx, perUploadTimeout)
	defer end()

	sdkLogSetup.Do(configureSDKLogging)
	id := uploadSeq.Add(1)
	mark := sdkLog.mark()
	// An abandoned call may still read its data after Upload returns.
	data := bytes.Clone(ciphertext)
	s := storageSDK
	roots, err := runBounded(uploadCtx, func(ctx context.Context) ([]common.Hash, error) {
		return s.upload(ctx, indexerURL, rpcURL, data, signer, callLogger(id))
	})
	// A blob above the fragment size (4 GiB) is split into several roots;
	// sealed records exactly one root per blob.
	if err == nil && len(roots) != 1 {
		err = fmt.Errorf("expected exactly one storage root, got %d", len(roots))
	}
	if err != nil {
		for _, line := range sdkLog.since(mark, id) {
			logger.Logf("0g-storage: %s", line)
		}
		return [32]byte{}, fmt.Errorf("0g-storage upload: %w", flatError{err})
	}
	logger.Logf("0g-storage upload OK: root=%s size=%dB", roots[0].Hex(), len(ciphertext))
	return roots[0], nil
}

// uploadContext returns the context an upload hands the SDK and the
// function that ends it. The context ends when ctx does or limit after the
// call, whichever comes first, and context.Cause says why
// (context.DeadlineExceeded at the limit); it keeps ctx's values. It has no
// deadline, even when ctx has one: the SDK's RPC provider applies its
// request timeout (RequestTimeout, 30s) only to contexts without a
// deadline, as the CLI's were (it ran on context.Background()). With one,
// a single stalled indexer or storage-node request could hold the upload
// for the whole limit instead of being cut off at 30s.
func uploadContext(ctx context.Context, limit time.Duration) (context.Context, func()) {
	sdkCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	if ctx.Err() != nil {
		cancel(context.Cause(ctx))
	}
	stopParent := context.AfterFunc(ctx, func() { cancel(context.Cause(ctx)) })
	timer := time.AfterFunc(limit, func() { cancel(context.DeadlineExceeded) })
	return sdkCtx, func() {
		timer.Stop()
		stopParent()
		cancel(nil)
	}
}

// runBounded runs f on its own goroutine and returns its result, or why
// ctx ended (context.Cause) as soon as it does, whichever comes first. A
// call that failed because ctx ended reports that cause too. A panic in f
// is returned as an error.
func runBounded(ctx context.Context, f func(context.Context) ([]common.Hash, error)) ([]common.Hash, error) {
	type result struct {
		roots []common.Hash
		err   error
	}
	done := make(chan result, 1) // buffered: an abandoned f never blocks
	go func() {
		var r result
		defer func() {
			if p := recover(); p != nil {
				r = result{err: fmt.Errorf("storage SDK panic: %v", p)}
			}
			done <- r
		}()
		r.roots, r.err = f(ctx)
	}()
	// The SDK's errors for an ended context wrap context.Canceled (the
	// context is cancelled with a cause, it has no deadline); report why it
	// ended instead.
	outcome := func(r result) ([]common.Hash, error) {
		if r.err != nil && ctx.Err() != nil && errors.Is(r.err, context.Canceled) {
			return nil, context.Cause(ctx)
		}
		return r.roots, r.err
	}
	select {
	case r := <-done:
		return outcome(r)
	case <-ctx.Done():
		// Prefer a result that arrived together with the deadline.
		select {
		case r := <-done:
			return outcome(r)
		default:
			return nil, context.Cause(ctx)
		}
	}
}

// ── The SDK's blocked submit goroutines ───────────────────────────────────

// The pinned SDK submits a blob larger than 2 MiB that is not on chain yet
// through contract.TransactWithGasAdjustment, which waits for the
// transaction's receipt; smaller ones (up to transfer's
// slowParallelMaxSize) through TransactWithGasAdjustmentNoReceipt, which
// starts no goroutine. TransactWithGasAdjustment's submit goroutine sleeps
// 30s after broadcasting, then sends on a channel with one slot. When the
// receipt wait fails before then -- the submission reverted, or the receipt
// query failed -- the function fills that slot itself and returns, and the
// goroutine blocks on its send for good (contract/contract.go:276 at the
// pinned version), keeping what it references. The CLI exited after each
// upload; sealed is PID 1 and keeps every such goroutine. A failed upload is
// tried again on every drift tick, with up to three submissions each time
// (indexer.Client.SplitableUpload), so nothing else bounds them.
//
// Until the SDK is fixed, Upload bounds them: it does not start an upload of
// a blob over 2 MiB that could take the SDK's live submit goroutines past
// maxSubmitGoroutines. Live means asleep, running or blocked: the goroutine
// of a submission that went through ends 30s after its broadcast, a blocked
// one only with the process. A refused upload fails like any other and is
// tried again on a later tick; once blocked goroutines alone fill the cap,
// blobs over 2 MiB are refused until sealed restarts. Smaller blobs never
// take that path and are never refused. TestSubmitPathSource_Unchanged
// fails when an SDK bump changes the files this was checked against.
const (
	// receiptPathAbove: the SDK submits a blob larger than this through
	// TransactWithGasAdjustment (transfer's slowParallelMaxSize).
	receiptPathAbove = 2 * 1024 * 1024
	// submitsPerUpload is the most submissions one upload makes, each with
	// a submit goroutine of its own: indexer.Client.SplitableUpload's
	// attempts with NRetries unset and FullTrusted set (uploadOption), one
	// TransactWithGasAdjustment each.
	submitsPerUpload = 3
	// submitGoroutineFunc is the function the SDK's submit goroutine runs.
	submitGoroutineFunc = "github.com/0gfoundation/0g-storage-client/contract.TransactWithGasAdjustment.func1"
)

// maxSubmitGoroutines caps the SDK's live submit goroutines; a blocked one
// keeps some tens of kilobytes. A variable only so tests can lower it.
var maxSubmitGoroutines = 64

// submitGoroutines counts the SDK's live submit goroutines. A variable only
// so tests can substitute a count.
var submitGoroutines = countSubmitGoroutines

// admitUpload says why an upload of size bytes must not start, or returns
// nil. It relies on Upload's callers running one upload at a time (the
// drift loop does); uploads started together could each pass the check.
func admitUpload(size int) error {
	if size <= receiptPathAbove {
		return nil
	}
	if n := submitGoroutines(); n+submitsPerUpload > maxSubmitGoroutines {
		return fmt.Errorf("refused a %d-byte blob: the storage SDK holds %d submit goroutines, and an upload over 2 MiB could take it past %d (those of failed submissions end only when sealed restarts)",
			size, n, maxSubmitGoroutines)
	}
	return nil
}

// countSubmitGoroutines counts the goroutines running submitGoroutineFunc.
// It looks at each goroutine's innermost 32 frames (runtime.GoroutineProfile),
// which hold that function for one asleep or blocked in it; one that is
// deep in sending its transaction can be missed, which at a check is at
// most a send an abandoned call still had on the wire at its deadline.
func countSubmitGoroutines() int {
	n, _ := runtime.GoroutineProfile(nil)
	var recs []runtime.StackRecord
	for {
		recs = make([]runtime.StackRecord, n+n/4+16)
		var ok bool
		if n, ok = runtime.GoroutineProfile(recs); ok {
			break
		}
	}
	count := 0
	for _, r := range recs[:n] {
		frames := runtime.CallersFrames(r.Stack())
		for {
			f, more := frames.Next()
			if f.Function == submitGoroutineFunc {
				count++
				break
			}
			if !more {
				break
			}
		}
	}
	return count
}

// flatError renders an error on one line and keeps its chain for
// errors.Is / errors.As.
type flatError struct{ err error }

func (e flatError) Error() string { return strings.Join(strings.Fields(e.err.Error()), " ") }
func (e flatError) Unwrap() error { return e.err }

// ── SDK logging ────────────────────────────────────────────────────────────

// The SDK logs through logrus: partly through the logger in its options,
// which each Upload call gets of its own (callLogger), and partly through
// logrus's package-level logger, shared by every call. Both land in sdkLog,
// each line tagged with the call it came from, or with 0 for the
// package-level logger. A failed call's report (since) leaves out the lines
// of other calls' own loggers -- an earlier call abandoned at its deadline
// keeps logging while it winds down -- but keeps every package-level line,
// since those cannot be attributed.
var (
	sdkLogSetup sync.Once
	sdkLog      = &logRing{max: sdkLogLines}
	uploadSeq   atomic.Uint64 // numbers Upload calls from 1
)

const (
	// sdkLogLines is how many of the SDK's most recent log lines are kept
	// for a failed upload's report.
	sdkLogLines = 64
	// sdkLogLineMax caps one kept line; the SDK logs whole receipts.
	sdkLogLineMax = 1024
)

// configureSDKLogging points logrus's package-level logger -- used only by
// the storage SDK in this binary -- at sdkLog (see configureLogger).
func configureSDKLogging() {
	configureLogger(logrus.StandardLogger(), sdkLog.writer(0))
}

// callLogger returns the logger Upload call id hands the SDK's clients.
func callLogger(id uint64) *logrus.Logger {
	l := logrus.New()
	configureLogger(l, sdkLog.writer(id))
	return l
}

// configureLogger sets l up for the SDK: output to out, plain text, no
// colour, the CLI's default level. Its exit hook panics instead of
// exiting, so a fatal log in the SDK's calling goroutine fails the upload
// (runBounded recovers it) rather than the process; the upload path has no
// such call today.
func configureLogger(l *logrus.Logger, out io.Writer) {
	l.SetOutput(out)
	l.SetFormatter(&logrus.TextFormatter{DisableColors: true, FullTimestamp: true})
	l.SetLevel(logrus.InfoLevel)
	l.ExitFunc = func(code int) {
		panic(fmt.Sprintf("storage SDK requested process exit (status %d)", code))
	}
}

// logRing keeps the last max lines written to it, numbered from 1, each
// with the call it came from (0: not attributed to a call).
type logRing struct {
	mu    sync.Mutex
	max   int
	lines []logLine
	total uint64 // lines ever written
}

type logLine struct {
	call uint64
	text string
}

// writer returns an io.Writer whose lines go into r tagged with call.
func (r *logRing) writer(call uint64) io.Writer { return ringWriter{r, call} }

type ringWriter struct {
	r    *logRing
	call uint64
}

func (w ringWriter) Write(p []byte) (int, error) {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if len(line) > sdkLogLineMax {
			line = line[:sdkLogLineMax] + " ...(truncated)"
		}
		w.r.lines = append(w.r.lines, logLine{w.call, line})
		if len(w.r.lines) > w.r.max {
			w.r.lines = w.r.lines[len(w.r.lines)-w.r.max:]
		}
		w.r.total++
	}
	return len(p), nil
}

// mark returns the number of lines written so far.
func (r *logRing) mark() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// since returns the kept lines written after mark by call or not
// attributed to any call, preceded by a note when lines written after mark
// (by any call) have already been dropped.
func (r *logRing) since(mark, call uint64) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.total - mark
	if n == 0 {
		return nil
	}
	var out []string
	if n > uint64(len(r.lines)) {
		out = append(out, fmt.Sprintf("(%d earlier lines dropped)", n-uint64(len(r.lines))))
		n = uint64(len(r.lines))
	}
	for _, l := range r.lines[uint64(len(r.lines))-n:] {
		if l.call == call || l.call == 0 {
			out = append(out, l.text)
		}
	}
	return out
}
