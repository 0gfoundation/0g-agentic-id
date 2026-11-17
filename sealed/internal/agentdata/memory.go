package agentdata

import (
	"fmt"
	"sort"
	"strings"
)

// frontMatter reads a memory file's leading "---" block as key: value
// fields (quotes around a value are dropped). nil when there is none.
func frontMatter(b []byte) map[string]string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return nil
	}
	end := strings.Index(s[4:], "\n---")
	if end < 0 {
		return nil
	}
	fields := map[string]string{}
	for _, line := range strings.Split(s[4:4+end], "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		fields[k] = v
	}
	return fields
}

// Public reports whether a memory file is marked for hosted programs:
// `visibility: public` in its front matter. Anything else is private.
func Public(b []byte) bool {
	fm := frontMatter(b)
	return fm != nil && strings.EqualFold(fm["visibility"], "public")
}

// PublicIndex is the MEMORY.md a job sees: one line per public memory,
// "- [name](file) — description", sorted by file.
func PublicIndex(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for f := range files {
		if f != "MEMORY.md" {
			names = append(names, f)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, f := range names {
		fm := frontMatter(files[f])
		name := fm["name"]
		if name == "" {
			name = strings.TrimSuffix(f, ".md")
		}
		desc := strings.Join(strings.Fields(fm["description"]), " ")
		fmt.Fprintf(&b, "- [%s](%s) — %s\n", name, f, desc)
	}
	return []byte(b.String())
}
