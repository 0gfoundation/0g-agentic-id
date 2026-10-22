package manifest

import (
	"errors"
	"fmt"
	"io/fs"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

// Producer helpers: the manifest entry for one directory or file of an
// agent-writable role directory, with the same rules in every adapter.
//
//   - An entry that is gone, or that the privsep read rules refuse (a
//     link, a special file, a foreign hard link), is left out (ok=false);
//     the refusal is logged once per path (privsep.Refused).
//   - An entry over its size limit (privsep.ErrTooLarge) is the agent's
//     data and is not left out, which would commit the role without it: it
//     becomes a Held entry, logged once per path, so that entry keeps its
//     committed version while every other entry of the role keeps
//     committing. A directory is over its limit when its archive would
//     exceed what PackDir packs (ArchiveLimit); a file when it is larger
//     than privsep.LimitTracked.
//   - Any other error is returned; the caller fails the role for this pass.

// DirEntryOf packs the directory full (PackDirDigest: the archive is
// hashed, not held) as the dir entry name+"/".
func DirEntryOf(full, name string) (e Entry, ok bool, err error) {
	path := name + "/"
	hash, size, err := PackDirDigest(full)
	switch {
	case err == nil:
		return Entry{Path: path, Kind: EntryDir, ContentHash: hash, Size: size}, true, nil
	case errors.Is(err, fs.ErrNotExist) || privsep.Refused(full, err):
		return Entry{}, false, nil
	case errors.Is(err, privsep.ErrTooLarge):
		return hold(full, path, EntryDir, err), true, nil
	}
	return Entry{}, false, fmt.Errorf("pack %s: %w", full, err)
}

// FileEntryOf reads the regular file full, at most privsep.LimitTracked
// bytes, as the file entry name. transform, when non-nil, maps the content
// before it is hashed (an adapter that strips platform-injected text);
// e.Size is then the transformed size, which a caller that does not track
// empty files checks (on an entry that is not held).
func FileEntryOf(full, name string, transform func([]byte) []byte) (e Entry, ok bool, err error) {
	content, err := privsep.ReadFile(full, privsep.LimitTracked)
	switch {
	case err == nil:
		if transform != nil {
			content = transform(content)
		}
		return Entry{Path: name, Kind: EntryFile, ContentHash: HashHex(content), Size: len(content)}, true, nil
	case errors.Is(err, fs.ErrNotExist) || privsep.Refused(full, err):
		return Entry{}, false, nil
	case errors.Is(err, privsep.ErrTooLarge):
		return hold(full, name, EntryFile, err), true, nil
	}
	return Entry{}, false, fmt.Errorf("read %s: %w", full, err)
}

func hold(full, path string, kind EntryKind, err error) Entry {
	logger.Once("manifest.held:"+full, "manifest: %q is over its size limit (%v); its committed version is kept, and changes to it are not committed until it is back under the limit", full, err)
	return Held(path, kind)
}
