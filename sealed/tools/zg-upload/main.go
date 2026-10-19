// Command zg-upload uploads one file to 0G Storage through the
// 0g-storage-client Go SDK and prints the file's storage root.
//
// sealed (internal/dataplane.Upload) runs it once per encrypted iData blob.
// It replaces `0g-storage-client upload`, which accepts the signing key only
// through its --key flag: a process's argument list is readable by every
// local user via /proc/<pid>/cmdline, so the key must not travel there.
// zg-upload reads the hex-encoded signing key from stdin instead (a single
// line, at most maxKeyInput bytes, optionally 0x-prefixed) and takes every
// other parameter as a flag. It has no --key flag.
//
// Usage (the key is written to stdin by the caller):
//
//	zg-upload --file PATH --indexer URL --url RPC_URL \
//	    [--expected-replica N] [--skip-tx=BOOL] [--fast-mode=BOOL] \
//	    [--full-trusted=BOOL] [--method min|max|random|N]
//
// Boolean flags take the --flag=value form; a separate value word is
// rejected rather than silently ending flag parsing.
//
// On Linux the helper first marks itself non-dumpable (PR_SET_DUMPABLE=0),
// so other unprivileged processes, its own uid included, cannot read its
// memory, environment or descriptors through /proc while it holds the key.
//
// Flag defaults match `0g-storage-client upload`. Parameters that CLI
// exposes but sealed never sets are fixed at the CLI's defaults
// (uploadOption, providerOption), and the SDK calls mirror the CLI's
// indexer upload path (cmd/upload.go at the pinned version in go.mod).
//
// Output contract: on success stdout carries exactly one line,
// "root = 0x<64 hex>", and the exit status is 0. SDK logs go to stderr. On
// failure the last stderr line is "zg-upload: <error>" and the exit status
// is non-zero (2 for usage errors, 1 otherwise).
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/openweb3/web3go"
	"github.com/openweb3/web3go/interfaces"
	"github.com/openweb3/web3go/signers"
	"github.com/sirupsen/logrus"
)

// maxKeyInput caps how much of stdin is read for the key. A key line is at
// most 2 ("0x") + 64 hex + 2 ("\r\n") = 68 bytes; anything past the cap is
// rejected rather than buffered.
const maxKeyInput = 128

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

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

var (
	errKeyFormat = errors.New("signing key on stdin must be a single line of 64 hex characters, optionally 0x-prefixed")
	errKeyEmpty  = errors.New("no signing key on stdin")
)

// options are the per-invocation upload parameters taken from flags.
type options struct {
	file            string
	indexer         string
	url             string
	expectedReplica uint
	skipTx          bool
	fastMode        bool
	fullTrusted     bool
	method          string
}

// uploadFunc performs the upload and returns the storage roots. sdkUpload
// is the production implementation; tests substitute a stub.
type uploadFunc func(ctx context.Context, o options, priv *ecdsa.PrivateKey) ([]common.Hash, error)

func main() {
	// First, before the key is read: become non-dumpable (harden_linux.go).
	if err := hardenProcess(); err != nil {
		fmt.Fprintf(os.Stderr, "zg-upload: set non-dumpable: %s\n", oneLine(err))
		os.Exit(exitError)
	}
	logrus.SetOutput(os.Stderr)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, DisableColors: true})
	logrus.SetLevel(logrus.InfoLevel)
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, sdkUpload))
}

// run is main without the process globals: it parses args, reads the key
// from stdin, uploads through up and writes the result line to stdout.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, up uploadFunc) int {
	o, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintf(stderr, "zg-upload: %s\n", oneLine(err))
		return exitUsage
	}
	priv, err := readKey(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "zg-upload: %s\n", oneLine(err))
		return exitUsage
	}
	roots, err := up(ctx, o, priv)
	if err != nil {
		fmt.Fprintf(stderr, "zg-upload: upload: %s\n", oneLine(err))
		return exitError
	}
	// A file above the fragment size (4 GiB) is split into several roots.
	// sealed records exactly one root per blob, so refuse rather than print
	// something its parser would misread.
	if len(roots) != 1 {
		fmt.Fprintf(stderr, "zg-upload: expected exactly one storage root, got %d\n", len(roots))
		return exitError
	}
	if _, err := io.WriteString(stdout, formatRoot(roots[0])); err != nil {
		fmt.Fprintf(stderr, "zg-upload: write result: %s\n", oneLine(err))
		return exitError
	}
	return exitOK
}

// parseFlags parses the upload flags. Defaults match `0g-storage-client
// upload`. Positional arguments are rejected (without echoing them, in case
// a caller misplaced a secret there): with the standard flag package a bare
// value after a boolean flag (`--skip-tx true`) would otherwise end flag
// parsing and silently drop every flag after it.
func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("zg-upload", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.file, "file", "", "file to upload (required)")
	fs.StringVar(&o.indexer, "indexer", "", "0G Storage indexer URL (required)")
	fs.StringVar(&o.url, "url", "", "fullnode RPC URL used to submit the storage transaction (required)")
	fs.UintVar(&o.expectedReplica, "expected-replica", 1, "expected number of replications to upload")
	fs.BoolVar(&o.skipTx, "skip-tx", true, "skip sending the transaction on chain if it already exists")
	fs.BoolVar(&o.fastMode, "fast-mode", true, "fast mode (no receipt wait, root-based upload for small files)")
	fs.BoolVar(&o.fullTrusted, "full-trusted", true, "use full trusted nodes")
	fs.StringVar(&o.method, "method", "min", "node selection method: min, max, random, or a positive number")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: zg-upload --file PATH --indexer URL --url RPC_URL [flags] < key")
		fmt.Fprintln(fs.Output(), "The hex-encoded signing key is read from stdin (one line); there is no --key flag.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if n := fs.NArg(); n > 0 {
		return options{}, fmt.Errorf("unexpected positional arguments (%d); boolean flags take the --flag=value form", n)
	}
	var missing []string
	for _, f := range []struct{ name, val string }{{"file", o.file}, {"indexer", o.indexer}, {"url", o.url}} {
		if f.val == "" {
			missing = append(missing, "--"+f.name)
		}
	}
	if len(missing) > 0 {
		return options{}, fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}
	if !validMethod(o.method) {
		return options{}, fmt.Errorf("invalid --method %q: want min, max, random, or a positive number", o.method)
	}
	return o, nil
}

func validMethod(m string) bool {
	switch m {
	case "min", "max", "random":
		return true
	}
	n, err := strconv.ParseUint(m, 10, 64)
	return err == nil && n > 0
}

// readKey reads the hex-encoded secp256k1 signing key from r: a single
// line, optionally 0x-prefixed, optionally newline-terminated, at most
// maxKeyInput bytes. Buffers holding key material are zeroed before
// returning. Errors never quote the input.
func readKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, maxKeyInput+1)
	defer clear(buf)
	n, err := io.ReadFull(r, buf)
	switch {
	case err == nil:
		return nil, fmt.Errorf("signing key on stdin exceeds %d bytes", maxKeyInput)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		// Short read: the whole input is in buf[:n].
	default:
		return nil, fmt.Errorf("read signing key from stdin: %w", err)
	}
	line := buf[:n]
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(line) == 0 {
		return nil, errKeyEmpty
	}
	if len(line) >= 2 && line[0] == '0' && (line[1] == 'x' || line[1] == 'X') {
		line = line[2:]
	}
	if len(line) != 2*32 {
		return nil, errKeyFormat
	}
	raw := make([]byte, 32)
	defer clear(raw)
	// The hex error is dropped on purpose: it quotes the offending byte.
	if _, err := hex.Decode(raw, line); err != nil {
		return nil, errKeyFormat
	}
	priv, err := crypto.ToECDSA(raw)
	if err != nil {
		return nil, errors.New("signing key on stdin is not a valid secp256k1 private key")
	}
	return priv, nil
}

// formatRoot renders the success line sealed parses
// (sealed/internal/dataplane rootLineRegexp).
func formatRoot(root common.Hash) string {
	return "root = " + root.Hex() + "\n"
}

// oneLine flattens an error onto one line so it stays the last line of
// stderr, which is what sealed surfaces as the failure summary.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// providerOption mirrors the CLI's RPC defaults (cmd/root.go).
func providerOption() providers.Option {
	return providers.Option{
		RetryCount:     cliRPCRetryCount,
		RetryInterval:  cliRPCRetryPeriod,
		RequestTimeout: cliRPCTimeout,
	}
}

// uploadOption maps the flags onto the SDK option exactly as
// `0g-storage-client upload` does for an invocation that sets only the
// flags zg-upload exposes.
func uploadOption(o options, submitter common.Address) transfer.UploadOption {
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
		ExpectedReplica:  o.expectedReplica,
		SkipTx:           o.skipTx,
		FastMode:         o.fastMode,
		Method:           o.method,
		FullTrusted:      o.fullTrusted,
		FragmentSize:     cliFragmentSize,
		BatchSize:        cliBatchSize,
	}
}

// sdkUpload performs the SDK calls of the CLI's --indexer upload path. The
// signer is built from the parsed key rather than from a key string, so no
// immutable copy of the hex key is created.
func sdkUpload(ctx context.Context, o options, priv *ecdsa.PrivateKey) ([]common.Hash, error) {
	signer := signers.NewPrivateKeySigner(priv)
	clientOpt := web3go.ClientOption{Option: providerOption()}
	clientOpt.WithSignerManager(signers.NewSignerManager([]interfaces.Signer{signer}))
	w3client, err := web3go.NewClientWithOption(o.url, clientOpt)
	if err != nil {
		return nil, fmt.Errorf("connect to fullnode: %w", err)
	}
	defer w3client.Close()

	file, err := core.Open(o.file)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	indexerClient, err := indexer.NewClient(o.indexer, indexer.IndexerClientOption{
		ProviderOption: providerOption(),
		LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
		Routines:       runtime.GOMAXPROCS(0),
		Contract:       &transfer.ContractAddress{},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize indexer client: %w", err)
	}
	defer indexerClient.Close()

	_, roots, err := indexerClient.SplitableUpload(ctx, w3client, file, uploadOption(o, signer.Address()))
	if err != nil {
		return nil, err
	}
	return roots, nil
}
