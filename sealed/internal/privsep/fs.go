//go:build linux

package privsep

// Root-side file access inside trees the agent user can write.
//
// sealed runs as root and reads, writes, removes and chowns files under the
// framework homes, which the agent user owns and may change at any moment.
// Path-based os.* calls resolve symbolic links at every component and open
// whatever object sits at the leaf, so in those trees they would let the
// agent decide which file root actually touches. Every helper here instead
// walks the path one component at a time, each opened relative to its
// parent's descriptor with O_NOFOLLOW, and acts on the object it opened:
//
//   - a symbolic link anywhere in the path is refused (ErrUnsafePath);
//   - a read first opens the leaf O_PATH, which never blocks and runs no
//     driver whatever the object is, and opens it for reading only once
//     that descriptor shows a regular file; anything else (a FIFO, a
//     socket, a device) is refused (ErrUnsafePath). That second open is
//     non-blocking, so a lease the file's owner holds on it fails the read
//     at once (ErrBusy) instead of holding root until the lease is broken;
//   - a regular file with more than one link is read only when it has the
//     same owner as the directory holding it;
//   - ReadFile and ReadTail are size-bounded (ErrTooLarge for ReadFile);
//     Open returns the file itself, and its callers bound what they read;
//   - a write creates a fresh temp file (O_EXCL|O_NOFOLLOW) in the opened
//     parent and renames it over the destination, which is never opened, so
//     the result is always a regular file and an existing link at that name
//     is replaced rather than followed; a directory at that name is removed
//     (RemoveAll's walk) and replaced too. New entries take the owner of the
//     directory they are created in: agent-owned inside a handed-over tree,
//     root-owned everywhere else.
//
// Paths must be absolute and clean (no "..", no trailing slash). The
// helpers do not depend on the uid split being active; they are equally
// correct with it off.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/logger"
)

var (
	// ErrUnsafePath marks a path the helpers refuse to act on: a symbolic
	// link in any component, a leaf that is not a regular file, or a
	// multiply-linked file owned by someone other than its directory's owner.
	ErrUnsafePath = errors.New("unsafe path")
	// ErrTooLarge marks a read that exceeded its size limit.
	ErrTooLarge = errors.New("file exceeds the size limit")
	// ErrBusy marks a read refused for now because another process holds
	// a lease on the file (fcntl F_SETLEASE): opening it would wait for
	// the lease to be broken. It says nothing about the file's content or
	// presence, so callers must not treat the file as absent (or commit
	// its deletion): they skip the file for this pass and retry later.
	ErrBusy = errors.New("file is leased by another process; try again later")
)

const (
	// LimitTracked bounds a read of a chain-tracked file.
	LimitTracked int64 = 64 << 20
	// LimitConfig bounds a read of a config or bookkeeping file.
	LimitConfig int64 = 8 << 20

	// maxTreeDepth bounds OwnTree's recursive walk.
	maxTreeDepth = 128
)

// unsafeError carries the reason a path was refused; errors.Is matches it
// against ErrUnsafePath.
type unsafeError struct{ why string }

func (e *unsafeError) Error() string        { return "refused: " + e.why }
func (e *unsafeError) Is(target error) bool { return target == ErrUnsafePath }

func pathErr(op, path string, err error) error {
	return &fs.PathError{Op: op, Path: path, Err: err}
}

func unsafeErr(op, path, why string) error {
	return pathErr(op, path, &unsafeError{why: why})
}

// checkPath requires an absolute, clean path. filepath.Clean of an absolute
// path removes every "..", so a clean path cannot climb.
func checkPath(op, p string) error {
	if p == "" || p[0] != '/' || filepath.Clean(p) != p || strings.IndexByte(p, 0) >= 0 {
		return unsafeErr(op, p, "path must be absolute and clean")
	}
	return nil
}

// checkLeaf is checkPath for operations that need a named entry inside a
// parent directory (anything but "/").
func checkLeaf(op, p string) error {
	if err := checkPath(op, p); err != nil {
		return err
	}
	if p == "/" {
		return unsafeErr(op, p, "operation needs a named entry")
	}
	return nil
}

func openat(dirfd int, name string, flags int, mode uint32) (int, error) {
	for {
		fd, err := unix.Openat(dirfd, name, flags, mode)
		if err != unix.EINTR {
			return fd, err
		}
	}
}

const dirPathFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// classify turns an open failure on name (relative to dirfd) into the error
// the helpers return: a symbolic link becomes ErrUnsafePath, anything else
// keeps its errno so os.IsNotExist and friends still work.
func classify(dirfd int, name, op, path string, err error) error {
	if err == unix.ELOOP {
		return unsafeErr(op, path, "symbolic link in path")
	}
	if err == unix.ENOTDIR {
		var st unix.Stat_t
		if unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return unsafeErr(op, path, "symbolic link in path")
		}
	}
	return pathErr(op, path, err)
}

// walkDir opens dir as an O_PATH directory descriptor, resolving each
// component relative to the previous one without following links.
func walkDir(op, dir string) (int, error) {
	fd, err := openat(unix.AT_FDCWD, "/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, pathErr(op, "/", err)
	}
	rest := strings.TrimPrefix(dir, "/")
	for rest != "" {
		var comp string
		comp, rest, _ = strings.Cut(rest, "/")
		next, err := openat(fd, comp, dirPathFlags, 0)
		if err != nil {
			err = classify(fd, comp, op, dir, err)
			unix.Close(fd)
			return -1, err
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}

// openParent opens the directory holding path and returns it with the leaf
// name.
func openParent(op, path string) (int, string, error) {
	if err := checkLeaf(op, path); err != nil {
		return -1, "", err
	}
	pfd, err := walkDir(op, filepath.Dir(path))
	if err != nil {
		return -1, "", err
	}
	return pfd, filepath.Base(path), nil
}

// openRegular opens path for reading and returns its descriptor only when
// the leaf is a regular file that passes the link-count rule.
//
// The leaf is opened O_PATH first: that open never blocks and runs no
// driver, whatever sits at the name. Only once that descriptor shows a
// regular file is the file opened for reading, through the descriptor's
// /proc/self/fd entry, which names the object already checked rather than
// resolving the path again. That open is non-blocking: the owner of a
// file may hold a lease on it (F_SETLEASE needs only the file's uid), and
// a blocking open would then wait for the lease to be broken
// (lease-break-time, 45 s by default) — again on every read, since the
// holder can take the lease anew. It fails at once with ErrBusy instead,
// and the descriptor is made blocking again before it is returned (which
// changes nothing for a regular file's reads).
func openRegular(op, path string) (int, error) {
	pfd, base, err := openParent(op, path)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	pathfd, err := openat(pfd, base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, classify(pfd, base, op, path, err)
	}
	defer unix.Close(pathfd)
	var st unix.Stat_t
	if err := unix.Fstat(pathfd, &st); err != nil {
		return -1, pathErr(op, path, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFLNK:
		return -1, unsafeErr(op, path, "symbolic link in path")
	default:
		return -1, unsafeErr(op, path, "not a regular file")
	}
	if st.Nlink > 1 {
		var pst unix.Stat_t
		if err := unix.Fstat(pfd, &pst); err != nil || pst.Uid != st.Uid {
			return -1, unsafeErr(op, path, "multiply-linked file not owned by its directory's owner")
		}
	}
	fd, err := openat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", pathfd), unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err == unix.EWOULDBLOCK {
		return -1, pathErr(op, path, ErrBusy)
	}
	if err != nil {
		return -1, pathErr(op, path, err)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return -1, pathErr(op, path, err)
	}
	return fd, nil
}

// Open opens a regular file for reading without following links (see the
// file comment for the rules). Open does not bound the read: the caller
// decides how much of the file it consumes (ReadFile and ReadTail are the
// bounded readers).
func Open(path string) (*os.File, error) {
	fd, err := openRegular("open", path)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// ReadFile reads a regular file through Open, refusing with ErrTooLarge
// when it holds more than limit bytes. The buffer is sized from the file's
// size up front (capped at limit), so reading a file costs about its size
// once rather than the doubling growth of io.ReadAll.
func ReadFile(path string, limit int64) ([]byte, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tooLarge := pathErr("read", path, fmt.Errorf("%w (%d bytes)", ErrTooLarge, limit))
	var size int64
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}
	if size > limit {
		return nil, tooLarge
	}
	data, err := readAll(io.LimitReader(f, limit+1), make([]byte, 0, size+1))
	if err != nil {
		return nil, pathErr("read", path, err)
	}
	if int64(len(data)) > limit {
		return nil, tooLarge
	}
	return data, nil
}

// readAll is io.ReadAll into a caller-sized buffer: it grows b only when
// the reader yields more than b's capacity.
func readAll(r io.Reader, b []byte) ([]byte, error) {
	for {
		if len(b) == cap(b) {
			b = append(b, 0)[:len(b)]
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err == io.EOF {
			return b, nil
		}
		if err != nil {
			return b, err
		}
	}
}

// ReadTail reads at most the last max bytes of a regular file through Open.
// For files another uid keeps appending to, such as a framework process's
// log: the read stays bounded however large the file has grown.
func ReadTail(path string, max int64) ([]byte, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > max {
		if _, err := f.Seek(fi.Size()-max, io.SeekStart); err != nil {
			return nil, pathErr("read", path, err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, pathErr("read", path, err)
	}
	return data, nil
}

// DirEntry is one directory entry with the lstat-style result taken
// relative to the directory's descriptor when it was listed. Info never
// re-resolves the path.
type DirEntry struct {
	name string
	st   unix.Stat_t
}

func (e DirEntry) Name() string               { return e.name }
func (e DirEntry) IsDir() bool                { return e.st.Mode&unix.S_IFMT == unix.S_IFDIR }
func (e DirEntry) IsRegular() bool            { return e.st.Mode&unix.S_IFMT == unix.S_IFREG }
func (e DirEntry) Type() fs.FileMode          { return fileMode(e.st.Mode).Type() }
func (e DirEntry) Info() (fs.FileInfo, error) { return fileInfo{name: e.name, st: e.st}, nil }

// ReadDir lists a directory without following links (the directory itself
// and every component above it must be real directories). Entries are
// sorted by name; entries removed while listing are left out.
func ReadDir(path string) ([]DirEntry, error) {
	if err := checkPath("readdir", path); err != nil {
		return nil, err
	}
	pfd, err := walkDir("readdir", path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	dfd, err := openat(pfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, pathErr("readdir", path, err)
	}
	defer unix.Close(dfd)
	names, err := readNames(dfd)
	if err != nil {
		return nil, pathErr("readdir", path, err)
	}
	out := make([]DirEntry, 0, len(names))
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if err == unix.ENOENT {
				continue
			}
			return nil, pathErr("readdir", filepath.Join(path, n), err)
		}
		out = append(out, DirEntry{name: n, st: st})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// readNames lists the names in an open directory through a duplicate
// descriptor, leaving dfd open for *at calls.
func readNames(dfd int) ([]string, error) {
	nfd, err := unix.FcntlInt(uintptr(dfd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(nfd), "")
	defer f.Close()
	return f.Readdirnames(-1)
}

// Lstat stats path without following a link at any component.
func Lstat(path string) (fs.FileInfo, error) {
	if err := checkPath("lstat", path); err != nil {
		return nil, err
	}
	if path == "/" {
		var st unix.Stat_t
		if err := unix.Lstat("/", &st); err != nil {
			return nil, pathErr("lstat", path, err)
		}
		return fileInfo{name: "/", st: st}, nil
	}
	pfd, base, err := openParent("lstat", path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, pathErr("lstat", path, err)
	}
	return fileInfo{name: base, st: st}, nil
}

// MkdirAll creates path and any missing parents without following links.
// Existing components must be real directories. Directories it creates
// take the owner of the directory they are created in.
func MkdirAll(path string, perm fs.FileMode) error {
	if err := checkPath("mkdir", path); err != nil {
		return err
	}
	fd, err := openat(unix.AT_FDCWD, "/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return pathErr("mkdir", "/", err)
	}
	rest := strings.TrimPrefix(path, "/")
	for rest != "" {
		var comp string
		comp, rest, _ = strings.Cut(rest, "/")
		next, err := openat(fd, comp, dirPathFlags, 0)
		if err == unix.ENOENT {
			merr := unix.Mkdirat(fd, comp, uint32(perm.Perm()))
			if merr != nil && merr != unix.EEXIST {
				unix.Close(fd)
				return pathErr("mkdir", path, merr)
			}
			next, err = openat(fd, comp, dirPathFlags, 0)
			if err == nil && merr == nil {
				if cerr := inheritOwner(fd, next, true); cerr != nil {
					unix.Close(next)
					unix.Close(fd)
					return pathErr("mkdir", path, cerr)
				}
			}
		}
		if err != nil {
			err = classify(fd, comp, "mkdir", path, err)
			unix.Close(fd)
			return err
		}
		unix.Close(fd)
		fd = next
	}
	unix.Close(fd)
	return nil
}

// EnsureDir makes dir a real directory. dir must be base or lie inside it.
// base and everything above it are handled as MkdirAll handles them:
// created when missing, refused when a component is a symbolic link. Below
// base — inside a tree the agent may rearrange — a component that is not a
// directory (a symbolic link, a regular file, a socket, ...) is removed, the
// entry itself and never what it points at, and a directory is created in
// its place, owned like MkdirAll's; each replacement is logged once per
// path. Root code that owns the shape of a directory inside an agent tree
// (restore, the framework's own working directories) uses it, so that
// whatever the agent left at that name cannot keep it from starting.
func EnsureDir(base, dir string, perm fs.FileMode) error {
	if err := checkPath("mkdir", base); err != nil {
		return err
	}
	if err := checkPath("mkdir", dir); err != nil {
		return err
	}
	rel := ""
	switch {
	case dir == base:
	case base == "/":
		rel = strings.TrimPrefix(dir, "/")
	case strings.HasPrefix(dir, base+"/"):
		rel = strings.TrimPrefix(dir, base+"/")
	default:
		return unsafeErr("mkdir", dir, "not inside "+base)
	}
	if err := MkdirAll(base, perm); err != nil {
		return err
	}
	fd, err := walkDir("mkdir", base)
	if err != nil {
		return err
	}
	cur := strings.TrimSuffix(base, "/")
	for rel != "" {
		var comp string
		comp, rel, _ = strings.Cut(rel, "/")
		cur += "/" + comp
		next, err := ensureChildDir(fd, comp, cur, perm)
		unix.Close(fd)
		if err != nil {
			return err
		}
		fd = next
	}
	unix.Close(fd)
	return nil
}

// ensureChildDir opens name in the directory fd as a directory (O_PATH),
// creating it when missing and replacing whatever non-directory sits there.
// An entry that keeps changing under it is given up on after maxRelists
// attempts.
func ensureChildDir(fd int, name, full string, perm fs.FileMode) (int, error) {
	for attempt := 0; ; attempt++ {
		next, err := openat(fd, name, dirPathFlags, 0)
		if err == nil {
			return next, nil
		}
		switch err {
		case unix.ENOENT:
			merr := unix.Mkdirat(fd, name, uint32(perm.Perm()))
			if merr == nil {
				next, err := openat(fd, name, dirPathFlags, 0)
				if err == nil {
					if cerr := inheritOwner(fd, next, true); cerr != nil {
						unix.Close(next)
						return -1, pathErr("mkdir", full, cerr)
					}
					return next, nil
				}
			} else if merr != unix.EEXIST {
				return -1, pathErr("mkdir", full, merr)
			}
		case unix.ELOOP, unix.ENOTDIR:
			var st unix.Stat_t
			if serr := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); serr == nil && st.Mode&unix.S_IFMT != unix.S_IFDIR {
				if uerr := unix.Unlinkat(fd, name, 0); uerr != nil && uerr != unix.ENOENT {
					return -1, pathErr("mkdir", full, uerr)
				}
				logger.Once("privsep.ensuredir:"+full, "privsep: %q was %s, not a directory; replaced it with one", full, describeType(st.Mode))
			}
		default:
			return -1, pathErr("mkdir", full, err)
		}
		if attempt >= maxRelists {
			return -1, pathErr("mkdir", full, errors.New("the entry kept changing while it was being made a directory"))
		}
	}
}

// describeType names the file type in mode for a log line.
func describeType(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return "a symbolic link"
	case unix.S_IFREG:
		return "a regular file"
	case unix.S_IFDIR:
		return "a directory"
	case unix.S_IFSOCK:
		return "a socket"
	case unix.S_IFIFO:
		return "a FIFO"
	default:
		return "a device or other special file"
	}
}

// inheritOwner gives the object behind fd the owner of the directory
// behind parentfd. Only root can give a file away; for any other euid the
// creator's ownership stands. emptyPath selects AT_EMPTY_PATH (fd may be an
// O_PATH descriptor).
func inheritOwner(parentfd, fd int, emptyPath bool) error {
	if os.Geteuid() != 0 {
		return nil
	}
	var pst, st unix.Stat_t
	if err := unix.Fstat(parentfd, &pst); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if pst.Uid == st.Uid && pst.Gid == st.Gid {
		return nil
	}
	if emptyPath {
		return unix.Fchownat(fd, "", int(pst.Uid), int(pst.Gid), unix.AT_EMPTY_PATH)
	}
	return unix.Fchown(fd, int(pst.Uid), int(pst.Gid))
}

// WriteFile replaces path with a regular file holding data: a temp file is
// created next to it (O_EXCL|O_NOFOLLOW), given perm and the parent
// directory's owner, and renamed over the destination. The destination is
// never opened, so a link there is replaced, not followed. A directory at
// the destination, which rename(2) cannot replace with a file, is removed
// first (without following links, as RemoveAll does) and logged once: the
// caller owns that name, and something else sitting there must not keep
// the file from being written.
func WriteFile(path string, data []byte, perm fs.FileMode) error {
	_, err := WriteFileFrom(path, bytes.NewReader(data), perm)
	return err
}

// WriteFileFrom is WriteFile with the content streamed from r rather than
// held in memory. It returns the number of bytes written. A read error from
// r leaves the destination untouched.
func WriteFileFrom(path string, r io.Reader, perm fs.FileMode) (int64, error) {
	pfd, base, err := openParent("write", path)
	if err != nil {
		return 0, err
	}
	defer unix.Close(pfd)
	tmp, err := tempName(base)
	if err != nil {
		return 0, pathErr("write", path, err)
	}
	fd, err := openat(pfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return 0, pathErr("write", path, err)
	}
	done := false
	defer func() {
		if !done {
			_ = unix.Unlinkat(pfd, tmp, 0)
		}
	}()
	f := os.NewFile(uintptr(fd), tmp)
	n, err := io.Copy(f, r)
	if err != nil {
		f.Close()
		return n, pathErr("write", path, err)
	}
	if err := finishWrite(f, pfd, perm); err != nil {
		return n, pathErr("write", path, err)
	}
	err = unix.Renameat(pfd, tmp, pfd, base)
	if err == unix.EISDIR {
		// A directory at the destination: remove it, then rename once more.
		logger.Once("privsep.write-over-dir:"+path, "privsep: %q is a directory; replacing it with a regular file", path)
		if rerr := removeAllAt(pfd, base, path); rerr != nil {
			return n, pathErr("write", path, fmt.Errorf("%v (removing the directory there: %v)", err, rerr))
		}
		err = unix.Renameat(pfd, tmp, pfd, base)
	}
	if err != nil {
		return n, pathErr("write", path, err)
	}
	done = true
	return n, nil
}

// finishWrite sets the temp file's mode and owner and closes it.
func finishWrite(f *os.File, pfd int, perm fs.FileMode) error {
	if err := f.Chmod(perm.Perm()); err != nil {
		f.Close()
		return err
	}
	if err := inheritOwner(pfd, int(f.Fd()), false); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func tempName(base string) (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	if len(base) > 100 {
		base = base[:100]
	}
	return "." + base + ".sealed-tmp-" + hex.EncodeToString(b[:]), nil
}

// Remove removes one file or empty directory without following links (a
// link at path is removed itself).
func Remove(path string) error {
	pfd, base, err := openParent("remove", path)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	err = unix.Unlinkat(pfd, base, 0)
	if err == unix.EISDIR {
		err = unix.Unlinkat(pfd, base, unix.AT_REMOVEDIR)
	}
	if err != nil {
		return pathErr("remove", path, err)
	}
	return nil
}

// RemoveAll removes path and everything below it without following links.
// A missing path is not an error.
//
// The walk is iterative and holds at most maxHeldDirs directory
// descriptors whatever the depth, so it removes any tree the filesystem can
// hold, as os.RemoveAll does. Each directory is entered by name from its
// parent's descriptor without following a link. Going back up to a parent
// whose descriptor was released opens ".." of the directory just emptied
// and uses it only if it is the same directory (device and inode) that was
// entered on the way down; if the tree was rearranged so that it is not,
// RemoveAll stops with an error rather than act on another directory.
func RemoveAll(path string) error {
	pfd, base, err := openParent("removeall", path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer unix.Close(pfd)
	return removeAllAt(pfd, base, path)
}

// removeAllHook, when set (tests only), is called by removeAllAt at the
// points where another process changing the tree matters: "reopen" just
// before a released parent is reopened through "..", "rmdir" just before an
// emptied directory is removed from its parent. path names the directory
// being removed.
var removeAllHook func(event, path string)

const (
	// maxHeldDirs bounds the directory descriptors RemoveAll keeps open.
	maxHeldDirs = 32
	// maxRelists bounds how often RemoveAll lists one directory again
	// because entries kept appearing in it while it was being emptied.
	maxRelists = 5
)

// rmFrame is one directory on RemoveAll's stack.
type rmFrame struct {
	fd       int      // O_RDONLY directory descriptor; -1 while released
	dev, ino uint64   // identity recorded when the directory was entered
	name     string   // entry name in the parent's directory
	full     string   // for errors
	names    []string // children not yet removed; nil = not listed yet
	relists  int
}

// isDir reports whether name in dirfd is a directory (not following a link).
func isDir(dirfd int, name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR
}

// enterDir opens name in dirfd as a directory without following a link.
func enterDir(dirfd int, name, full string) (*rmFrame, error) {
	fd, err := openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &rmFrame{fd: fd, dev: uint64(st.Dev), ino: st.Ino, name: name, full: full}, nil
}

func removeAllAt(rootParent int, rootName, rootFull string) error {
	var stack []*rmFrame
	defer func() {
		for _, f := range stack {
			if f.fd >= 0 {
				unix.Close(f.fd)
			}
		}
	}()
	// parentFD returns the descriptor of the directory holding stack[i],
	// reopening a released parent through ".." of stack[i] (still open).
	parentFD := func(i int) (int, error) {
		if i == 0 {
			return rootParent, nil
		}
		p := stack[i-1]
		if p.fd >= 0 {
			return p.fd, nil
		}
		if removeAllHook != nil {
			removeAllHook("reopen", stack[i].full)
		}
		fd, err := openat(stack[i].fd, "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, pathErr("removeall", p.full, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || uint64(st.Dev) != p.dev || st.Ino != p.ino {
			unix.Close(fd)
			return -1, pathErr("removeall", p.full, errors.New("directory moved while it was being removed"))
		}
		p.fd = fd
		return fd, nil
	}

	for attempt := 0; ; attempt++ {
		err := unix.Unlinkat(rootParent, rootName, 0)
		if err == nil || err == unix.ENOENT {
			return nil
		}
		if !isDir(rootParent, rootName) {
			return pathErr("removeall", rootFull, err)
		}
		f, err := enterDir(rootParent, rootName, rootFull)
		if err == unix.ENOENT {
			return nil
		}
		if (err == unix.ENOTDIR || err == unix.ELOOP) && attempt < maxRelists {
			continue // replaced by a non-directory meanwhile: unlink it
		}
		if err != nil {
			return pathErr("removeall", rootFull, err)
		}
		stack = []*rmFrame{f}
		break
	}

	for len(stack) > 0 {
		top := stack[len(stack)-1]
		if top.names == nil {
			names, err := readNames(top.fd)
			if err != nil {
				return pathErr("removeall", top.full, err)
			}
			top.names = append([]string{}, names...)
		}
		if n := len(top.names); n > 0 {
			name := top.names[n-1]
			top.names = top.names[:n-1]
			child := top.full + "/" + name
			err := unix.Unlinkat(top.fd, name, 0)
			if err == nil || err == unix.ENOENT {
				continue
			}
			if !isDir(top.fd, name) {
				return pathErr("removeall", child, err)
			}
			f, err := enterDir(top.fd, name, child)
			switch {
			case err == unix.ENOENT:
				continue
			case err == unix.ENOTDIR || err == unix.ELOOP:
				top.names = append(top.names, name) // replaced meanwhile: unlink it next
				if top.relists++; top.relists > maxRelists {
					return pathErr("removeall", child, err)
				}
				continue
			case err != nil:
				return pathErr("removeall", child, err)
			}
			stack = append(stack, f)
			if i := len(stack) - 1 - maxHeldDirs; i >= 0 && stack[i].fd >= 0 {
				unix.Close(stack[i].fd)
				stack[i].fd = -1
			}
			continue
		}
		// top is empty: remove it from its parent.
		i := len(stack) - 1
		pfd, err := parentFD(i)
		if err != nil {
			return err
		}
		unix.Close(top.fd)
		top.fd = -1
		if removeAllHook != nil {
			removeAllHook("rmdir", top.full)
		}
		err = unix.Unlinkat(pfd, top.name, unix.AT_REMOVEDIR)
		switch {
		case err == nil || err == unix.ENOENT:
			stack = stack[:i]
		case err == unix.ENOTEMPTY || err == unix.EEXIST:
			// Filled again meanwhile: enter it again and list it afresh.
			if top.relists++; top.relists > maxRelists {
				return pathErr("removeall", top.full, unix.ENOTEMPTY)
			}
			f, err := enterDir(pfd, top.name, top.full)
			if err == unix.ENOENT {
				stack = stack[:i]
				continue
			}
			if err != nil {
				return pathErr("removeall", top.full, err)
			}
			if f.dev != top.dev || f.ino != top.ino {
				// Replaced by another directory meanwhile: that one is
				// removed the same way.
				top.dev, top.ino = f.dev, f.ino
			}
			top.fd, top.names = f.fd, nil
		default:
			return pathErr("removeall", top.full, err)
		}
	}
	return nil
}

// Chmod sets the permission bits of path without following a link at any
// component; a link at path is refused, and so is a regular file with more
// than one link whose owner is not the owner of the directory holding it
// (the read rule: such a file may be another name for a file elsewhere).
// The entry is opened O_PATH (any file type, including a socket) and its
// mode is set through that descriptor's /proc/self/fd entry, which names
// the object already opened instead of resolving the path again; fchmod
// itself does not accept an O_PATH descriptor.
func Chmod(path string, perm fs.FileMode) error {
	pfd, base, err := openParent("chmod", path)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	fd, err := openat(pfd, base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return classify(pfd, base, "chmod", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return pathErr("chmod", path, err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unsafeErr("chmod", path, "symbolic link at the leaf")
	}
	if st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink > 1 {
		var pst unix.Stat_t
		if err := unix.Fstat(pfd, &pst); err != nil || pst.Uid != st.Uid {
			return unsafeErr("chmod", path, "multiply-linked file not owned by its directory's owner")
		}
	}
	if err := unix.Chmod(fmt.Sprintf("/proc/self/fd/%d", fd), uint32(perm.Perm())); err != nil {
		return pathErr("chmod", path, err)
	}
	return nil
}

// Rename renames oldpath to newpath without following links: both parent
// directories are opened component by component (a link in either path is
// refused) and a link at oldpath is renamed itself. Like rename(2), an
// existing entry at newpath is replaced.
func Rename(oldpath, newpath string) error {
	return rename(oldpath, newpath, false)
}

// RenameNoReplace is Rename that fails with fs.ErrExist instead of
// replacing an entry already at newpath.
func RenameNoReplace(oldpath, newpath string) error {
	return rename(oldpath, newpath, true)
}

func rename(oldpath, newpath string, noReplace bool) error {
	opfd, obase, err := openParent("rename", oldpath)
	if err != nil {
		return err
	}
	defer unix.Close(opfd)
	npfd, nbase, err := openParent("rename", newpath)
	if err != nil {
		return err
	}
	defer unix.Close(npfd)
	if !noReplace {
		if err := unix.Renameat(opfd, obase, npfd, nbase); err != nil {
			return pathErr("rename", oldpath, err)
		}
		return nil
	}
	err = unix.Renameat2(opfd, obase, npfd, nbase, unix.RENAME_NOREPLACE)
	if err == unix.EINVAL || err == unix.ENOSYS {
		// A filesystem without RENAME_NOREPLACE: check, then rename. The
		// window between the two only matters to whoever can write the
		// destination directory, and replacing its own entry there is
		// something it could do itself.
		var st unix.Stat_t
		switch serr := unix.Fstatat(npfd, nbase, &st, unix.AT_SYMLINK_NOFOLLOW); serr {
		case nil:
			err = unix.EEXIST
		case unix.ENOENT:
			err = unix.Renameat(opfd, obase, npfd, nbase)
		default:
			err = serr
		}
	}
	if err != nil {
		return pathErr("rename", oldpath, err)
	}
	return nil
}

// ── refusal reporting ──────────────────────────────────────────────────────

// Refused reports whether err is an ErrUnsafePath refusal by these helpers
// (a link, a non-regular file, a foreign hard link) and logs it the first
// time it is seen for path. Callers that walk agent-writable trees use it to
// skip such entries: the agent put something there that is not a file root
// will read, which is the same as the file being absent.
//
// ErrTooLarge is deliberately not a refusal here. A tracked file that grew
// past its limit is still the agent's data; a caller that skipped it would
// commit state without it. Callers treat it as an error instead, so the
// last committed version stands.
func Refused(path string, err error) bool {
	if !errors.Is(err, ErrUnsafePath) {
		return false
	}
	logger.Once("privsep.refused:"+path, "privsep: skipping %q: %v", path, err)
	return true
}

// ── fs.FileInfo over a stat result ─────────────────────────────────────────

type fileInfo struct {
	name string
	st   unix.Stat_t
}

func (fi fileInfo) Name() string       { return fi.name }
func (fi fileInfo) Size() int64        { return fi.st.Size }
func (fi fileInfo) Mode() fs.FileMode  { return fileMode(fi.st.Mode) }
func (fi fileInfo) ModTime() time.Time { return time.Unix(fi.st.Mtim.Unix()) }
func (fi fileInfo) IsDir() bool        { return fi.st.Mode&unix.S_IFMT == unix.S_IFDIR }
func (fi fileInfo) Sys() any           { return &fi.st }

func fileMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	case unix.S_IFLNK:
		mode |= fs.ModeSymlink
	case unix.S_IFIFO:
		mode |= fs.ModeNamedPipe
	case unix.S_IFSOCK:
		mode |= fs.ModeSocket
	case unix.S_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFBLK:
		mode |= fs.ModeDevice
	}
	if m&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if m&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

// ── handing trees to the agent user ────────────────────────────────────────

// OwnTree recursively chowns root to the agent user. Best-effort, no-op
// without the split. Adapters call it on their framework trees only, never
// on $HOME (see guardHandover). The walk:
//
//   - is fd-relative: every entry is opened O_PATH|O_NOFOLLOW relative to
//     its parent's descriptor and chowned through that descriptor
//     (AT_EMPTY_PATH), so a name swapped between listing and chown can only
//     redirect the chown to another object inside the same directory;
//   - skips symbolic links, special files and regular files with more than
//     one link (a multiply-linked file may also live outside the tree);
//   - stays on the tree root's filesystem and stops descending after
//     maxTreeDepth levels;
//   - skips the chown for entries the agent already owns.
func OwnTree(root string) {
	c := credential()
	if c == nil {
		return
	}
	if err := ownTree(root, c.Uid, c.Gid); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logger.Logf("privsep: hand over %s: %v", root, err)
	}
}

// ownTree is OwnTree with the target identity injected, so tests can run it
// without an agent account.
func ownTree(root string, uid, gid uint32) error {
	if err := guardHandover("chown", root); err != nil {
		return err
	}
	pfd, base, err := openParent("chown", root)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	fd, err := openat(pfd, base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return classify(pfd, base, "chown", root, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return pathErr("chown", root, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unsafeErr("chown", root, "tree root is not a directory")
	}
	return ownDir(fd, &st, root, uid, gid, st.Dev, 0)
}

func chownFD(fd int, st *unix.Stat_t, uid, gid uint32) error {
	if st.Uid == uid && st.Gid == gid {
		return nil
	}
	return unix.Fchownat(fd, "", int(uid), int(gid), unix.AT_EMPTY_PATH)
}

// ownDir chowns the directory behind fd (an O_PATH descriptor) and walks
// its entries. Per-entry failures are logged and skipped: a best-effort
// handover must not stop at the first entry the agent removed meanwhile.
func ownDir(fd int, st *unix.Stat_t, path string, uid, gid uint32, dev uint64, depth int) error {
	if err := chownFD(fd, st, uid, gid); err != nil {
		return pathErr("chown", path, err)
	}
	if depth >= maxTreeDepth {
		logger.Once("privsep.handover-depth:"+path, "privsep: hand over %q: deeper than %d levels, not descending", path, maxTreeDepth)
		return nil
	}
	dfd, err := openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return pathErr("chown", path, err)
	}
	defer unix.Close(dfd)
	names, err := readNames(dfd)
	if err != nil {
		return pathErr("chown", path, err)
	}
	for _, n := range names {
		child := path + "/" + n
		cfd, err := openat(dfd, n, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue // removed meanwhile
		}
		var cst unix.Stat_t
		if err := unix.Fstat(cfd, &cst); err != nil {
			unix.Close(cfd)
			continue
		}
		switch cst.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if cst.Dev == dev {
				if err := ownDir(cfd, &cst, child, uid, gid, dev, depth+1); err != nil {
					logger.Logf("privsep: hand over %q: %v", child, err)
				}
			}
		case unix.S_IFREG:
			if cst.Nlink == 1 {
				if err := chownFD(cfd, &cst, uid, gid); err != nil {
					logger.Logf("privsep: chown %q: %v", child, err)
				}
			}
		}
		unix.Close(cfd)
	}
	return nil
}

// ownPath chowns one socket (not following a link at it) after the same
// guard OwnTree applies. The entry is opened O_PATH|O_NOFOLLOW, checked
// through that descriptor and chowned through it (AT_EMPTY_PATH), so the
// object chowned is the one checked. Anything but a socket is refused: its
// one caller hands over the sign socket, and a regular file at that name
// could be a hard link to a file root owns elsewhere.
func ownPath(path string, uid, gid uint32) error {
	if err := guardHandover("chown", path); err != nil {
		return err
	}
	pfd, base, err := openParent("chown", path)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	fd, err := openat(pfd, base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return classify(pfd, base, "chown", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return pathErr("chown", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return unsafeErr("chown", path, "not a socket")
	}
	if err := chownFD(fd, &st, uid, gid); err != nil {
		return pathErr("chown", path, err)
	}
	return nil
}

// guardHandover refuses to hand the agent "/" or any path that is, or is an
// ancestor of, something root relies on: root's home, a directory on
// sealed's PATH (as written and as resolved) or sealed's own executable.
// Owning a directory lets its owner rename and replace what is inside it,
// so handing over an ancestor of any of these would let the agent change
// what root later runs. It also refuses any path inside a protected tree
// (handoverTrees): sealed's state directory and the package directories of
// the binaries sealed runs, which a script toolchain loads in full.
func guardHandover(op, p string) error {
	if err := checkPath(op, p); err != nil {
		return err
	}
	if p == "/" {
		return unsafeErr(op, p, "refusing to hand over /")
	}
	for _, q := range handoverProtected() {
		if q == p || strings.HasPrefix(q, p+"/") {
			return unsafeErr(op, p, fmt.Sprintf("refusing to hand over a path that is or contains %s", q))
		}
	}
	for _, q := range handoverTrees() {
		if q == p || strings.HasPrefix(q, p+"/") || strings.HasPrefix(p, q+"/") {
			return unsafeErr(op, p, fmt.Sprintf("refusing to hand over a path inside or containing %s", q))
		}
	}
	return nil
}

// addPath appends p (when absolute) and its resolved form.
func addPath(out []string, p string) []string {
	if !filepath.IsAbs(p) {
		return out
	}
	out = append(out, filepath.Clean(p))
	if r, err := filepath.EvalSymlinks(p); err == nil {
		out = append(out, r)
	}
	return out
}

func handoverProtected() []string {
	out := []string{rootHome}
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		out = addPath(out, d)
	}
	if exe, err := os.Executable(); err == nil {
		out = addPath(out, exe)
	}
	return out
}

// protectedTools are the commands sealed runs by name, as root
// (RootCommand) or as the agent (AgentCommand, Sweep).
var protectedTools = []string{"npm", "node", "git", "uv", "0g-storage-client", "openclaw", "hermes", "pkill"}

// handoverTrees are the trees no handover may reach into: sealed's state
// directory, and for each protectedTools binary its package directory (the
// nearest directory above it holding a package.json, else the directory
// holding the binary). A script toolchain such as npm loads its whole
// package, not just the entry file LookPath checked.
func handoverTrees() []string {
	out := addPath(nil, StateDir)
	for _, name := range protectedTools {
		bin, err := LookPath(name)
		if err != nil {
			continue
		}
		out = addPath(out, packageRoot(bin))
	}
	return out
}

// packageRoot returns the nearest directory above the file bin that holds
// a package.json (within a few levels, and never "/" or root's home), else
// bin's own directory.
func packageRoot(bin string) string {
	dir := filepath.Dir(bin)
	for d, i := dir, 0; i < 8 && d != "/" && d != rootHome; d, i = filepath.Dir(d), i+1 {
		var st unix.Stat_t
		if unix.Lstat(filepath.Join(d, "package.json"), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG {
			return d
		}
	}
	return dir
}
