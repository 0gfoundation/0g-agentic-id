package servicehost

// Agent data: a release can ask for read-only copies of the agent's own
// committed data, so the program can work as the agent (its persona, its
// skills and its public long-term memory) inside the isolation.
//
// The grant is part of the published manifest, so callers who audit the
// release see that it reads agent data. Every temporary worker (a one-shot
// request or an execution) gets its own copy, staged by sealed before the
// worker starts and fixed for its whole life: the agent's later commits never
// change what a running job reads. The copy is the version committed on chain
// (scrubbed of credential values and known-format secrets, as committed), never
// uncommitted edits. Public memory is the agent's memory-public/ role whole;
// the private memory/ role is never staged. Workers also get SEAL_OWNER, the
// owner this container serves, so a reader can tell the memories that owner
// confirmed (`trusted_by`) from those inherited from an earlier owner.
// Coordinators get none. Owner-private memory, the conversation, the agent's
// inbox/outbox and home, credentials and the sign socket stay out of reach.
// An execution's status, and so its signed receipt, names the versions it
// read (AgentDataVersion).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"seal-verify/internal/privsep"
)

// Kinds of agent data a release can ask for.
const (
	AgentDataPersona      = "persona"
	AgentDataSkills       = "skills"
	AgentDataPublicMemory = "public_memory"
)

// AgentDataGrant is the manifest's `agent_data` field.
type AgentDataGrant struct {
	Persona      bool `json:"persona,omitempty"`
	Skills       bool `json:"skills,omitempty"`
	PublicMemory bool `json:"public_memory,omitempty"`
}

// Kinds lists the granted kinds in a fixed order.
func (g AgentDataGrant) Kinds() []string {
	var out []string
	if g.Persona {
		out = append(out, AgentDataPersona)
	}
	if g.Skills {
		out = append(out, AgentDataSkills)
	}
	if g.PublicMemory {
		out = append(out, AgentDataPublicMemory)
	}
	return out
}

// AgentDataVersion names the committed version of one kind of agent data a
// job read. ContentHash and DataHash are the role's chain pins (sha256 of the
// committed plaintext, and the 0G storage root the AgenticID entry holds), both
// empty when the role was never committed; they are what a caller checks
// against the chain. SnapshotHash is the sha256 over the files the job could
// read (AgentDataListingHash): the same set the pins name, hashed file by file,
// so whoever holds the plaintext files (the job's own copy, or the role's
// files) can check it without the iData manifest format.
type AgentDataVersion struct {
	Kind         string `json:"kind"`
	ContentHash  string `json:"content_hash,omitempty"`
	DataHash     string `json:"data_hash,omitempty"`
	SnapshotHash string `json:"snapshot_hash"`
	Files        int    `json:"files"`
}

// AgentDataPart is one kind a provider hands the manager: a sealed-owned
// directory of regular files that nothing writes while it is handed out, and
// its version.
type AgentDataPart struct {
	Dir     string
	Version AgentDataVersion
}

// AgentDataProvider is trusted wiring (sealed main): the committed data for a
// grant, and a release to call once the parts are copied.
type AgentDataProvider func(context.Context, AgentDataGrant) ([]AgentDataPart, func(), error)

// Bounds on what one job's copy may hold.
const (
	maxAgentDataBytes = 32 << 20
	maxAgentDataFiles = 4096
)

// agentDataDir names the subdirectory of a kind in the job's copy.
func agentDataDir(kind string) string {
	if kind == AgentDataPublicMemory {
		return "memory-public"
	}
	return kind
}

// AgentDataListingHash is the snapshot hash of a set of files: sha256 over
// "path NUL sha256hex LF" for each file, sorted by its slash-separated path.
func AgentDataListingHash(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		sum := sha256.Sum256(files[p])
		fmt.Fprintf(h, "%s\x00%s\n", p, hex.EncodeToString(sum[:]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// stageAgentData copies parts into dst, a new directory in a job's task
// directory, root-owned and read-only (files 0444, directories 0555, so the
// service identity reads it under its Landlock grant and cannot change it),
// with versions.json beside the kinds. It returns the versions.
func stageAgentData(dst string, parts []AgentDataPart) ([]AgentDataVersion, error) {
	if err := privsep.MkdirAll(dst, 0755); err != nil {
		return nil, err
	}
	budget := struct{ bytes, files int64 }{maxAgentDataBytes, maxAgentDataFiles}
	var dirs []string
	versions := make([]AgentDataVersion, 0, len(parts))
	for _, part := range parts {
		target := filepath.Join(dst, agentDataDir(part.Version.Kind))
		if err := copyTree(part.Dir, target, &budget.bytes, &budget.files, &dirs); err != nil {
			return nil, fmt.Errorf("agent data %s: %w", part.Version.Kind, err)
		}
		versions = append(versions, part.Version)
	}
	b, err := json.MarshalIndent(map[string]any{"versions": versions}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := privsep.WriteFile(filepath.Join(dst, "versions.json"), append(b, '\n'), 0444); err != nil {
		return nil, err
	}
	// Directories become read-only last, deepest first.
	dirs = append(dirs, dst)
	sort.Slice(dirs, func(i, j int) bool { return strings.Count(dirs[i], "/") > strings.Count(dirs[j], "/") })
	for _, d := range dirs {
		if err := privsep.Chmod(d, 0555); err != nil {
			return nil, err
		}
	}
	return versions, nil
}

// copyTree copies the regular files and directories below src into dst
// (created), refusing anything else, within the byte and file budgets.
func copyTree(src, dst string, bytesLeft, filesLeft *int64, dirs *[]string) error {
	if err := privsep.MkdirAll(dst, 0755); err != nil {
		return err
	}
	*dirs = append(*dirs, dst)
	entries, err := privsep.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		from, to := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		switch {
		case e.IsDir():
			if err := copyTree(from, to, bytesLeft, filesLeft, dirs); err != nil {
				return err
			}
		case e.IsRegular():
			if *filesLeft--; *filesLeft < 0 {
				return fmt.Errorf("more than %d files", maxAgentDataFiles)
			}
			b, err := privsep.ReadFile(from, *bytesLeft)
			if err != nil {
				return err
			}
			if *bytesLeft -= int64(len(b)); *bytesLeft < 0 {
				return fmt.Errorf("more than %d bytes", maxAgentDataBytes)
			}
			if err := privsep.WriteFile(to, b, 0444); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s is not a regular file or directory", e.Name())
		}
	}
	return nil
}

// agentDataEnv is what a worker reading agent data at dir is told: where
// the copy is, and the owner this container serves (SEAL_OWNER), against
// whom each memory's `trusted_by` is checked.
func (m *Manager) agentDataEnv(dir string) []string {
	env := []string{"SEAL_AGENT_DATA=" + dir}
	if m.owner != "" {
		env = append(env, "SEAL_OWNER="+m.owner)
	}
	return env
}

// stageAgentDataFor asks the provider for the grant's parts and stages them
// in dst.
func (m *Manager) stageAgentDataFor(ctx context.Context, grant AgentDataGrant, dst string) ([]AgentDataVersion, error) {
	if m.agentData == nil {
		return nil, fmt.Errorf("agent data is unavailable in this runtime")
	}
	parts, release, err := m.agentData(ctx, grant)
	if err != nil {
		return nil, fmt.Errorf("agent data: %w", err)
	}
	if release != nil {
		defer release()
	}
	return stageAgentData(dst, parts)
}
