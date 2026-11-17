// Package agentdata keeps the agent's committed data for hosted programs
// that ask for it (servicehost agent_data): the persona, the skills and the
// public long-term memory (the memory-public/ role whole), each at the
// version committed on chain.
//
// The provider keeps one directory per kind and committed version under
// sealed's root-only state directory, built from the agent's files when they
// hold exactly the committed version (their content hash, scrubbed as the
// uploader commits them, equals the chain pin). It builds one after every
// confirmed commit and on boot (Observe), and when a job asks for a version it
// has not built yet. When the files have moved on and the committed version
// was never built here, it refuses the job (ErrNotReady) rather than serve an
// uncommitted edit; the next commit builds it. The private memory/ role is
// never read: no kind maps to it, so a private memory never enters this
// directory.
package agentdata

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
	"seal-verify/internal/servicehost"
)

// Roles of the 0g-harness adapter each kind comes from.
const (
	RolePersona      = "APPEND_SYSTEM.md"
	RoleSkills       = "skills/"
	RolePublicMemory = "memory-public/"
)

var roleOf = map[string]string{
	servicehost.AgentDataPersona:      RolePersona,
	servicehost.AgentDataSkills:       RoleSkills,
	servicehost.AgentDataPublicMemory: RolePublicMemory,
}

// ErrNotReady: the committed version is not built in this container and the
// agent's files no longer hold it.
var ErrNotReady = errors.New("the committed version of the agent's data is not available in this container yet; it is after the agent's next commit")

// Source reads the agent's files as the uploader commits them (scrubbed).
type Source interface {
	EvolutionFor(ctx context.Context, role string) ([]byte, error)
	LoadEntry(ctx context.Context, role, path string) ([]byte, error)
}

// Chain returns a role's chain pins: the sha256 hex of its committed
// plaintext and its 0G storage root, both "" when it was never committed.
type Chain func(role string) (contentHash, dataHash string)

// keepVersions is how many built versions of a kind stay on disk.
const keepVersions = 3

type Provider struct {
	dir    string
	src    Source
	chain  Chain
	mu     sync.Mutex
	leases map[string]int // version directory -> jobs copying it
}

// New returns a provider keeping its versions below dir (root-only).
func New(dir string, src Source, chain Chain) *Provider {
	return &Provider{dir: dir, src: src, chain: chain, leases: map[string]int{}}
}

type versionFile struct {
	Version servicehost.AgentDataVersion `json:"version"`
}

// Parts returns the committed data for a grant (servicehost.AgentDataProvider).
// The directories stay on disk until release is called.
func (p *Provider) Parts(ctx context.Context, g servicehost.AgentDataGrant) ([]servicehost.AgentDataPart, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var parts []servicehost.AgentDataPart
	var held []string
	drop := func() { // with p.mu held
		for _, d := range held {
			if p.leases[d]--; p.leases[d] <= 0 {
				delete(p.leases, d)
			}
		}
	}
	for _, kind := range g.Kinds() {
		dir, v, err := p.versionLocked(ctx, kind)
		if err != nil {
			drop()
			return nil, nil, fmt.Errorf("%s: %w", kind, err)
		}
		p.leases[dir]++
		held = append(held, dir)
		parts = append(parts, servicehost.AgentDataPart{Dir: dir, Version: v})
	}
	var once sync.Once
	return parts, func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			drop()
		})
	}, nil
}

// Observe builds the committed version of role when the agent's files hold
// it. sealed calls it after every confirmed commit and on boot.
func (p *Provider) Observe(ctx context.Context, role string) {
	for kind, r := range roleOf {
		if r != role {
			continue
		}
		p.mu.Lock()
		if _, _, err := p.versionLocked(ctx, kind); err != nil && !errors.Is(err, ErrNotReady) {
			logger.Logf("agentdata: %s: %v", kind, err)
		}
		p.mu.Unlock()
	}
}

// versionLocked returns the directory and version of kind's committed
// version, building it from the agent's files when needed.
func (p *Provider) versionLocked(ctx context.Context, kind string) (string, servicehost.AgentDataVersion, error) {
	role := roleOf[kind]
	contentHash, dataHash := p.chain(role)
	if contentHash == "" || dataHash == "" {
		contentHash, dataHash = "", ""
	}
	key := contentHash
	if key == "" {
		key = "none"
	}
	base := filepath.Join(p.dir, kind)
	dir := filepath.Join(base, key)
	if v, ok := readVersion(dir); ok {
		return dir, v, nil
	}
	files := map[string][]byte{}
	if contentHash != "" {
		var err error
		if files, err = p.committedFiles(ctx, role, contentHash); err != nil {
			return "", servicehost.AgentDataVersion{}, err
		}
	}
	v := servicehost.AgentDataVersion{Kind: kind, ContentHash: contentHash, DataHash: dataHash,
		SnapshotHash: servicehost.AgentDataListingHash(files), Files: len(files)}
	if err := p.writeVersion(base, dir, files, v); err != nil {
		return "", servicehost.AgentDataVersion{}, err
	}
	p.pruneLocked(base, dir)
	return dir, v, nil
}

// committedFiles reads the role from the agent's files, provided they hold
// the committed version, as the files a job sees: every entry of the role (a
// directory entry unpacked into its files).
func (p *Provider) committedFiles(ctx context.Context, role, contentHash string) (map[string][]byte, error) {
	top, err := p.src.EvolutionFor(ctx, role)
	if err != nil {
		return nil, err
	}
	if sha256Hex(top) != contentHash {
		return nil, ErrNotReady
	}
	if role == RolePersona {
		if len(top) == 0 {
			return map[string][]byte{}, nil
		}
		return map[string][]byte{RolePersona: top}, nil
	}
	m, err := manifest.Unmarshal(top)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, e := range m.Entries {
		if e.IsHeld() {
			continue
		}
		b, err := p.src.LoadEntry(ctx, role, e.Path)
		if err != nil {
			return nil, err
		}
		if manifest.HashHex(b) != e.ContentHash {
			return nil, ErrNotReady // the files moved on while being read
		}
		switch {
		case e.Kind == manifest.EntryDir:
			tree, err := p.unpackToMap(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.Path, err)
			}
			for rel, data := range tree {
				files[strings.TrimSuffix(e.Path, "/")+"/"+rel] = data
			}
		default:
			files[e.Path] = b
		}
	}
	return files, nil
}

// writeVersion writes files into a fresh directory and renames it to dir.
func (p *Provider) writeVersion(base, dir string, files map[string][]byte, v servicehost.AgentDataVersion) error {
	if err := privsep.MkdirAll(base, 0700); err != nil {
		return err
	}
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	tmp := filepath.Join(base, ".build-"+hex.EncodeToString(r[:]))
	defer privsep.RemoveAll(tmp)
	if err := privsep.MkdirAll(tmp, 0700); err != nil {
		return err
	}
	for rel, data := range files {
		target := filepath.Join(tmp, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, tmp+string(filepath.Separator)) {
			return fmt.Errorf("path %q leaves the directory", rel)
		}
		if err := privsep.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err := privsep.WriteFile(target, data, 0600); err != nil {
			return err
		}
	}
	b, err := json.Marshal(versionFile{Version: v})
	if err != nil {
		return err
	}
	if err := privsep.WriteFileSync(tmp+".json", b, 0600); err != nil {
		return err
	}
	defer privsep.Remove(tmp + ".json")
	if err := privsep.Rename(tmp, dir); err != nil {
		return err
	}
	return privsep.Rename(tmp+".json", dir+".json")
}

func readVersion(dir string) (servicehost.AgentDataVersion, bool) {
	b, err := privsep.ReadFile(dir+".json", 1<<16)
	if err != nil {
		return servicehost.AgentDataVersion{}, false
	}
	if fi, err := privsep.Lstat(dir); err != nil || !fi.IsDir() {
		return servicehost.AgentDataVersion{}, false
	}
	var vf versionFile
	if json.Unmarshal(b, &vf) != nil || vf.Version.Kind == "" {
		return servicehost.AgentDataVersion{}, false
	}
	return vf.Version, true
}

// pruneLocked keeps the newest keepVersions versions of a kind (the one just
// returned among them) and every version a job is still copying.
func (p *Provider) pruneLocked(base, keep string) {
	entries, err := privsep.ReadDir(base)
	if err != nil {
		return
	}
	type built struct {
		dir string
		at  time.Time
	}
	var all []built
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		d := filepath.Join(base, e.Name())
		fi, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, built{d, fi.ModTime()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.After(all[j].at) })
	kept := 0
	for _, b := range all {
		if b.dir == keep || p.leases[b.dir] > 0 || kept < keepVersions {
			kept++
			continue
		}
		_ = privsep.RemoveAll(b.dir)
		_ = privsep.Remove(b.dir + ".json")
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// unpackToMap reads a directory entry's archive into a map of its files.
func (p *Provider) unpackToMap(tgz []byte) (map[string][]byte, error) {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	tmp := filepath.Join(p.dir, ".unpack-"+hex.EncodeToString(r[:]))
	if err := privsep.MkdirAll(tmp, 0700); err != nil {
		return nil, err
	}
	defer privsep.RemoveAll(tmp)
	if err := manifest.UnpackDir(tgz, tmp); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	var walk func(dir, rel string) error
	walk = func(dir, rel string) error {
		entries, err := privsep.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			r := name
			if rel != "" {
				r = rel + "/" + name
			}
			switch {
			case e.IsDir():
				if err := walk(filepath.Join(dir, name), r); err != nil {
					return err
				}
			case e.IsRegular():
				b, err := privsep.ReadFile(filepath.Join(dir, name), manifest.ArchiveLimit())
				if err != nil {
					return err
				}
				out[r] = b
			}
		}
		return nil
	}
	return out, walk(tmp, "")
}
