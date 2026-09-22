// Package studio exposes a semantic, adapter-declared view of mutable agent
// identity. It never accepts filesystem roots from callers.
package studio

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"seal-verify/internal/platform"
	"seal-verify/internal/state"
)

const (
	Schema       = "0g.studio.state.v1"
	maxFiles     = 64
	maxTotalSize = 1 << 20
)

type Kind string

const (
	KindPersonality Kind = "personality"
	KindSkills      Kind = "skills"
	KindMemory      Kind = "memory"
	KindFiles       Kind = "files"
)

type Operation string

const (
	OperationPut    Operation = "put"
	OperationDelete Operation = "delete"
)

type Activation string

const (
	ActivationActive          Activation = "active"
	ActivationNextSession     Activation = "next_session"
	ActivationRestartRequired Activation = "restart_required"
)

type Mode uint8

const (
	ModeSingleton Mode = iota
	ModeBundles
	ModeMarkdown
	ModeFiles
)

type Resource struct {
	Kind          Kind
	Format        string
	Activation    Activation
	Role          string
	Mode          Mode
	Root          string
	SingletonID   string
	Required      []string
	RequirePrefix []string
	RejectIDs     func() (map[string]bool, error)
	StripInjected bool
}

type Layout struct{ Resources []Resource }

type Provider interface {
	Name() string
	StudioLayout() Layout
	EvolutionFor(context.Context, string) ([]byte, error)
}

type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}
type Item struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}
type ResourceState struct {
	Kind       Kind       `json:"kind"`
	Format     string     `json:"format"`
	Activation Activation `json:"activation"`
	Items      []Item     `json:"items"`
}
type State struct {
	Schema    string          `json:"schema"`
	Framework string          `json:"framework"`
	Resources []ResourceState `json:"resources"`
}
type Checkpoint struct {
	Status      string `json:"status"`
	Role        string `json:"role"`
	ContentHash string `json:"content_hash"`
	DataHash    string `json:"data_hash,omitempty"`
}

const (
	CheckpointPending    = "pending"
	CheckpointConfirmed  = "confirmed"
	CheckpointSuperseded = "superseded"
)

type ReadResult struct {
	Kind       Kind       `json:"kind"`
	ID         string     `json:"id"`
	Revision   *string    `json:"revision"`
	Files      []File     `json:"files"`
	Activation Activation `json:"activation"`
	Checkpoint Checkpoint `json:"checkpoint"`
}
type MutationRequest struct {
	Operation      Operation `json:"operation"`
	Kind           Kind      `json:"kind"`
	ID             string    `json:"id"`
	Files          []File    `json:"files,omitempty"`
	IfRevision     *string   `json:"if_revision"`
	IdempotencyKey string    `json:"idempotency_key"`
}
type MutationResult struct {
	ReadResult
	MutationID string `json:"mutation_id"`
}
type Receipt struct {
	MutationID string     `json:"mutation_id"`
	Kind       Kind       `json:"kind"`
	ID         string     `json:"id"`
	Checkpoint Checkpoint `json:"checkpoint"`
}

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string  { return e.Message }
func IsConflict(err error) bool { var e *Error; return errors.As(err, &e) && e.Status == 409 }

type receiptRecord struct {
	mutationID     string
	kind           Kind
	id, role, hash string
}
type idemRecord struct {
	fingerprint string
	result      MutationResult
}
type Manager struct {
	mu          sync.Mutex
	provider    Provider
	agent       *state.Agent
	receipts    map[string]receiptRecord
	idempotency map[string]idemRecord
	order       []string
}

func New(provider Provider, agent *state.Agent) *Manager {
	return &Manager{provider: provider, agent: agent, receipts: map[string]receiptRecord{}, idempotency: map[string]idemRecord{}}
}

func (m *Manager) State() (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := State{Schema: Schema, Framework: m.provider.Name(), Resources: make([]ResourceState, 0, len(m.provider.StudioLayout().Resources))}
	for _, spec := range m.provider.StudioLayout().Resources {
		ids, err := listIDs(spec)
		if err != nil {
			return State{}, err
		}
		rs := ResourceState{Kind: spec.Kind, Format: spec.Format, Activation: spec.Activation, Items: make([]Item, 0, len(ids))}
		for _, id := range ids {
			files, err := readFiles(spec, id)
			if err != nil {
				return State{}, err
			}
			rs.Items = append(rs.Items, Item{ID: id, Revision: revision(files)})
		}
		out.Resources = append(out.Resources, rs)
	}
	return out, nil
}

func (m *Manager) Read(kind Kind, id string) (ReadResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result, err := m.readLocked(kind, id)
	if err != nil {
		return ReadResult{}, err
	}
	spec, _ := m.resource(kind)
	plaintext, err := m.provider.EvolutionFor(context.Background(), spec.Role)
	if err != nil {
		return ReadResult{}, err
	}
	result.Checkpoint = m.checkpoint(spec.Role, hash(plaintext))
	return result, nil
}

func (m *Manager) readLocked(kind Kind, id string) (ReadResult, error) {
	spec, err := m.resource(kind)
	if err != nil {
		return ReadResult{}, err
	}
	files, err := readFiles(spec, id)
	if os.IsNotExist(err) {
		return ReadResult{Kind: kind, ID: id, Revision: nil, Files: []File{}, Activation: spec.Activation, Checkpoint: m.checkpoint(spec.Role, "")}, nil
	}
	if err != nil {
		return ReadResult{}, err
	}
	rev := revision(files)
	return ReadResult{Kind: kind, ID: id, Revision: &rev, Files: files, Activation: spec.Activation, Checkpoint: m.checkpoint(spec.Role, "")}, nil
}

func (m *Manager) Mutate(ctx context.Context, req MutationRequest) (MutationResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validUUID(req.IdempotencyKey) {
		return MutationResult{}, bad("invalid_idempotency_key", "idempotency_key must be a UUID")
	}
	fingerprintBytes, _ := json.Marshal(req)
	fingerprint := hash(fingerprintBytes)
	if prior, ok := m.idempotency[req.IdempotencyKey]; ok {
		if prior.fingerprint != fingerprint {
			return MutationResult{}, conflict("idempotency_conflict", "idempotency_key was already used for another mutation")
		}
		result := prior.result
		if receipt, ok := m.receipts[result.MutationID]; ok {
			result.Checkpoint = m.checkpoint(receipt.role, receipt.hash)
		}
		return result, nil
	}
	spec, err := m.resource(req.Kind)
	if err != nil {
		return MutationResult{}, err
	}
	current, err := readFiles(spec, req.ID)
	if err != nil && !os.IsNotExist(err) {
		return MutationResult{}, err
	}
	var currentRevision *string
	if err == nil {
		v := revision(current)
		currentRevision = &v
	}
	if !sameRevision(currentRevision, req.IfRevision) {
		return MutationResult{}, conflict("revision_conflict", "if_revision does not match current revision")
	}
	switch req.Operation {
	case OperationPut:
		if err := validateFiles(spec, req.ID, req.Files); err != nil {
			return MutationResult{}, err
		}
		if err := writeFiles(spec, req.ID, req.Files); err != nil {
			return MutationResult{}, err
		}
	case OperationDelete:
		if len(req.Files) != 0 {
			return MutationResult{}, bad("invalid_delete", "delete must not include files")
		}
		if err := deleteItem(spec, req.ID); err != nil {
			return MutationResult{}, err
		}
	default:
		return MutationResult{}, bad("invalid_operation", "operation must be put or delete")
	}
	plaintext, err := m.provider.EvolutionFor(ctx, spec.Role)
	if err != nil {
		if currentRevision == nil {
			_ = deleteItem(spec, req.ID)
		} else {
			_ = writeFiles(spec, req.ID, current)
		}
		return MutationResult{}, fmt.Errorf("studio evolution %s: %w", spec.Role, err)
	}
	contentHash := hash(plaintext)
	m.agent.UpdateCurrentSnapshot(spec.Role, contentHash)
	readback, err := m.readLocked(req.Kind, req.ID)
	if err != nil {
		return MutationResult{}, err
	}
	readback.Checkpoint = m.checkpoint(spec.Role, contentHash)
	mutationID := newUUID()
	result := MutationResult{ReadResult: readback, MutationID: mutationID}
	m.receipts[mutationID] = receiptRecord{mutationID: mutationID, kind: req.Kind, id: req.ID, role: spec.Role, hash: contentHash}
	m.idempotency[req.IdempotencyKey] = idemRecord{fingerprint: fingerprint, result: result}
	m.order = append(m.order, req.IdempotencyKey)
	if len(m.order) > 256 {
		evicted := m.idempotency[m.order[0]]
		delete(m.idempotency, m.order[0])
		delete(m.receipts, evicted.result.MutationID)
		m.order = m.order[1:]
	}
	return result, nil
}

func (m *Manager) Receipt(id string) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.receipts[id]
	if !ok {
		return Receipt{}, &Error{Status: 404, Code: "receipt_not_found", Message: "mutation receipt not found"}
	}
	return Receipt{MutationID: id, Kind: rec.kind, ID: rec.id, Checkpoint: m.checkpoint(rec.role, rec.hash)}, nil
}

func (m *Manager) resource(kind Kind) (Resource, error) {
	for _, r := range m.provider.StudioLayout().Resources {
		if r.Kind == kind {
			return r, nil
		}
	}
	return Resource{}, &Error{Status: 404, Code: "resource_not_supported", Message: "resource kind is not supported by this adapter"}
}
func (m *Manager) checkpoint(role, expected string) Checkpoint {
	chain := m.agent.ChainEntry(role)
	cp := Checkpoint{Status: CheckpointPending, Role: role, ContentHash: expected}
	if expected != "" && chain.ContentHash == expected {
		cp.Status = CheckpointConfirmed
		cp.DataHash = chain.DataHash
	} else if expected != "" && m.agent.CurrentEntry(role).ContentHash != expected {
		cp.Status = CheckpointSuperseded
	}
	return cp
}

func listIDs(spec Resource) ([]string, error) {
	if spec.Mode == ModeSingleton {
		info, err := os.Lstat(spec.Root)
		if os.IsNotExist(err) {
			return []string{}, nil
		} else if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, bad("unsafe_path", "symbolic links are not allowed")
		}
		if spec.StripInjected {
			body, err := os.ReadFile(spec.Root)
			if err != nil {
				return nil, err
			}
			if len(platform.StripInjected(body)) == 0 {
				return []string{}, nil
			}
		}
		return []string{spec.SingletonID}, nil
	}
	entries, err := os.ReadDir(spec.Root)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	ids := []string{}
	if spec.Mode == ModeFiles {
		err := filepath.WalkDir(spec.Root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return bad("unsafe_path", "symbolic links are not allowed")
			}
			if entry.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(spec.Root, path)
			ids = append(ids, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(ids)
		return ids, nil
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, bad("unsafe_path", "symbolic links are not allowed")
		}
		switch spec.Mode {
		case ModeBundles:
			if e.IsDir() && validateID(spec, e.Name()) == nil {
				ids = append(ids, e.Name())
			}
		case ModeMarkdown:
			if !e.IsDir() && validateID(spec, e.Name()) == nil {
				ids = append(ids, e.Name())
			}
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func readFiles(spec Resource, id string) ([]File, error) {
	if err := validateID(spec, id); err != nil {
		return nil, err
	}
	path := itemPath(spec, id)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, bad("unsafe_path", "symbolic links are not allowed")
	}
	if !info.IsDir() {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, bad("invalid_utf8", "studio files must be UTF-8 text")
		}
		if len(b) > maxTotalSize {
			return nil, bad("too_large", "studio resource exceeds 1 MiB")
		}
		if spec.StripInjected {
			b = platform.StripInjected(b)
			if len(b) == 0 {
				return nil, os.ErrNotExist
			}
		}
		wirePath := filepath.Base(path)
		if spec.Mode == ModeFiles || spec.Mode == ModeMarkdown {
			wirePath = id
		}
		return []File{{Path: wirePath, Content: string(b)}}, nil
	}
	files := []File{}
	total := 0
	err = filepath.WalkDir(path, func(full string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return bad("unsafe_path", "symbolic links are not allowed")
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(path, full)
		b, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		if !utf8.Valid(b) {
			return bad("invalid_utf8", "studio files must be UTF-8 text")
		}
		total += len(b)
		if len(files) >= maxFiles || total > maxTotalSize {
			return bad("too_large", "studio resource exceeds 64 files or 1 MiB")
		}
		files = append(files, File{Path: filepath.ToSlash(rel), Content: string(b)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func validateFiles(spec Resource, id string, files []File) error {
	if err := validateID(spec, id); err != nil {
		return err
	}
	if len(files) == 0 || len(files) > maxFiles {
		return bad("invalid_files", "files must contain between 1 and 64 entries")
	}
	total := 0
	seen := map[string]bool{}
	for _, f := range files {
		if !safeRel(f.Path) || protectedPath(f.Path) {
			return bad("unsafe_path", "file path is not allowed")
		}
		if seen[f.Path] {
			return bad("duplicate_path", "duplicate file path")
		}
		seen[f.Path] = true
		if !utf8.ValidString(f.Content) {
			return bad("invalid_utf8", "studio files must be UTF-8 text")
		}
		if strings.Contains(f.Content, platform.MarkerStart) || strings.Contains(f.Content, platform.MarkerEnd) || strings.Contains(f.Content, "-----BEGIN PRIVATE KEY-----") {
			return bad("protected_content", "protected platform markers or secrets are not allowed")
		}
		total += len(f.Content)
		if total > maxTotalSize {
			return bad("too_large", "studio mutation exceeds 1 MiB")
		}
	}
	if spec.Mode == ModeSingleton {
		if len(files) != 1 || filepath.Base(files[0].Path) != filepath.Base(spec.Root) {
			return bad("invalid_files", "singleton resource requires its declared file")
		}
	}
	if spec.Mode == ModeFiles {
		if len(files) != 1 || files[0].Path != id {
			return bad("invalid_files", "files resource requires one file whose path equals id")
		}
	}
	if spec.Mode == ModeMarkdown {
		if len(files) != 1 || files[0].Path != id {
			return bad("invalid_files", "memory resource requires one file whose path equals id")
		}
	}
	for _, required := range spec.Required {
		if !seen[required] {
			return bad("invalid_bundle", "bundle is missing required file "+required)
		}
	}
	for _, prefix := range spec.RequirePrefix {
		found := false
		for path := range seen {
			if strings.HasPrefix(path, prefix) {
				found = true
				break
			}
		}
		if !found {
			return bad("invalid_bundle", "bundle is missing required path "+prefix)
		}
	}
	return nil
}

func writeFiles(spec Resource, id string, files []File) error {
	target := itemPath(spec, id)
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	if err := rejectSymlinkAncestors(spec.Root, target); err != nil {
		return err
	}
	if spec.Mode == ModeSingleton || spec.Mode == ModeMarkdown || spec.Mode == ModeFiles {
		content := []byte(files[0].Content)
		if spec.StripInjected {
			if current, err := os.ReadFile(target); err == nil {
				content = preserveInjected(current, content)
			}
		}
		return atomicFile(target, content)
	}
	stage, err := os.MkdirTemp(parent, ".studio-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, f := range files {
		dst := filepath.Join(stage, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(f.Content), 0o644); err != nil {
			return err
		}
	}
	return replacePath(stage, target)
}

func deleteItem(spec Resource, id string) error {
	if err := validateID(spec, id); err != nil {
		return err
	}
	target := itemPath(spec, id)
	if err := rejectSymlinkAncestors(spec.Root, target); err != nil {
		return err
	}
	if spec.StripInjected {
		current, err := os.ReadFile(target)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		preserved := preserveInjected(current, nil)
		if len(preserved) > 0 {
			return atomicFile(target, preserved)
		}
	}
	if _, err := os.Lstat(target); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	tomb, err := os.MkdirTemp(filepath.Dir(target), ".studio-delete-")
	if err != nil {
		return err
	}
	if err := os.Remove(tomb); err != nil {
		return err
	}
	if err := os.Rename(target, tomb); err != nil {
		return err
	}
	_ = os.RemoveAll(tomb)
	return nil
}
func itemPath(spec Resource, id string) string {
	if spec.Mode == ModeSingleton {
		return spec.Root
	}
	return filepath.Join(spec.Root, filepath.FromSlash(id))
}
func validateID(spec Resource, id string) error {
	if spec.Mode == ModeSingleton {
		if id != spec.SingletonID {
			return bad("invalid_id", "singleton id must be "+spec.SingletonID)
		}
		return nil
	}
	if !safeRel(id) || (spec.Mode != ModeFiles && strings.Contains(id, "/")) || protectedPath(id) {
		return bad("invalid_id", "resource id is not allowed")
	}
	if spec.Mode == ModeBundles && !regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`).MatchString(id) {
		return bad("invalid_id", "skill id must be a lowercase slug")
	}
	if spec.Mode == ModeMarkdown && !strings.HasSuffix(id, ".md") {
		return bad("invalid_id", "memory id must end in .md")
	}
	if spec.RejectIDs != nil {
		ids, err := spec.RejectIDs()
		if err != nil {
			return err
		}
		if ids[id] {
			return bad("protected_id", "resource id is managed by the framework")
		}
	}
	return nil
}

func preserveInjected(current, next []byte) []byte {
	start := strings.Index(string(current), platform.MarkerStart)
	if start < 0 {
		return next
	}
	relEnd := strings.Index(string(current[start:]), platform.MarkerEnd)
	if relEnd < 0 {
		return next
	}
	end := start + relEnd + len(platform.MarkerEnd)
	for end < len(current) && current[end] == '\n' {
		end++
	}
	out := append([]byte(nil), next...)
	if len(out) > 0 {
		out = append(out, '\n')
	}
	return append(out, current[start:end]...)
}
func safeRel(s string) bool {
	return s != "" && filepath.IsLocal(filepath.FromSlash(s)) && filepath.Clean(filepath.FromSlash(s)) == filepath.FromSlash(s)
}
func protectedPath(s string) bool {
	for _, segment := range strings.Split(filepath.ToSlash(s), "/") {
		l := strings.ToLower(segment)
		if strings.HasPrefix(l, ".") || l == "auth.json" || strings.HasPrefix(l, "secret") || strings.HasPrefix(l, "credential") || strings.HasSuffix(l, ".key") || strings.HasSuffix(l, ".pem") {
			return true
		}
	}
	return false
}
func rejectSymlinkAncestors(root, target string) error {
	for p := target; strings.HasPrefix(p, filepath.Clean(root)); p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return bad("unsafe_path", "symbolic links are not allowed")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if p == filepath.Clean(root) {
			break
		}
	}
	return nil
}
func atomicFile(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".studio-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0o644); err == nil {
		_, err = f.Write(b)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
func replacePath(stage, target string) error {
	backup := target + ".studio-backup"
	_ = os.RemoveAll(backup)
	if _, err := os.Lstat(target); err == nil {
		if err = os.Rename(target, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(stage, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	_ = os.RemoveAll(backup)
	return nil
}
func revision(files []File) string { b, _ := json.Marshal(files); return hash(b) }
func hash(b []byte) string         { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func sameRevision(got, want *string) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return *got == *want
}
func bad(code, msg string) error      { return &Error{Status: 400, Code: code, Message: msg} }
func conflict(code, msg string) error { return &Error{Status: 409, Code: code, Message: msg} }
func validUUID(s string) bool {
	return regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`).MatchString(s)
}
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// CanonicalTree is primarily useful to small adapters and tests that need a
// deterministic text-tree snapshot without exposing filesystem paths on wire.
func CanonicalTree(root string) ([]byte, error) {
	files := []File{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return bad("unsafe_path", "symbolic links are not allowed")
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, File{Path: filepath.ToSlash(rel), Content: string(b)})
		return nil
	})
	if os.IsNotExist(err) {
		return json.Marshal([]File{})
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return json.Marshal(files)
}
