// Package files serves the hub's shared folders over SSH channels.
//
// Wire protocol, one request per channel opened to "files.securdp":
//
//	request:  op \t arg1 \t arg2 \n          (tab-separated, one line)
//	response: ok [\t N] \n  then a body       or   err \t message \n
//
//	roots                  -> lines "name \t writable(0/1)"
//	list   path            -> lines "d|f \t size \t mtime(unix) \t name"
//	get    path  offset    -> "ok \t size" then the bytes from offset
//	thumb  path  px        -> "ok \t len" then a JPEG
//	put    path  size      -> client sends size bytes after the request line
//	mkdir  path / delete path / rename from to   -> "ok"
//
// Paths are virtual: "<shared folder name>/sub/dir/file". Every path is
// checked to stay inside its shared folder (no "..", no drive or stream
// syntax, symlinks/junctions resolved before the containment check).
package files

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"securdp/internal/config"
)

// Handler serves one request for one user.
type Handler struct {
	Folders []config.SharedFolder // the folders this user was granted
	User    string
	Log     func(format string, args ...any)
	Thumb   func(absPath string, px int) ([]byte, error) // nil = no thumbnails
}

var errBadPath = errors.New("invalid path")

const maxRequest = 8 << 10

// Serve reads one request from rw and writes the response.
func (h *Handler) Serve(rw io.ReadWriter) {
	br := bufio.NewReaderSize(rw, 64<<10)
	line, err := readLine(br)
	if err != nil {
		return
	}
	f := strings.Split(line, "\t")
	if err := h.dispatch(f, br, rw); err != nil {
		fmt.Fprintf(rw, "err\t%s\n", friendly(err))
	}
}

func readLine(br *bufio.Reader) (string, error) {
	var b []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return "", err
		}
		b = append(b, chunk...)
		if len(b) > maxRequest {
			return "", errors.New("request too long")
		}
		if !isPrefix {
			return string(b), nil
		}
	}
}

func arg(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}

func (h *Handler) log(op, vpath string) {
	if h.Log != nil {
		h.Log("FILE user=%s %s %q", h.User, op, vpath)
	}
}

func (h *Handler) dispatch(f []string, br *bufio.Reader, w io.Writer) error {
	switch f[0] {
	case "roots":
		var b strings.Builder
		b.WriteString("ok\n")
		for _, s := range h.Folders {
			fmt.Fprintf(&b, "%s\t%d\n", s.Name, b2i(s.Writable))
		}
		_, err := io.WriteString(w, b.String())
		return err

	case "list":
		abs, _, err := h.resolve(arg(f, 1), false, true)
		if err != nil {
			return err
		}
		entries, err := os.ReadDir(abs)
		if err != nil {
			return err
		}
		var b strings.Builder
		b.WriteString("ok\n")
		for _, e := range entries {
			info, err := e.Info()
			if err != nil || hiddenSystem(info) || strings.ContainsAny(e.Name(), "\t\n") {
				continue
			}
			kind, size := "f", info.Size()
			if info.IsDir() {
				kind, size = "d", 0
			}
			fmt.Fprintf(&b, "%s\t%d\t%d\t%s\n", kind, size, info.ModTime().Unix(), e.Name())
		}
		_, err = io.WriteString(w, b.String())
		return err

	case "get":
		abs, _, err := h.resolve(arg(f, 1), false, true)
		if err != nil {
			return err
		}
		off, _ := strconv.ParseInt(arg(f, 2), 10, 64)
		file, err := os.Open(abs)
		if err != nil {
			return err
		}
		defer file.Close()
		st, err := file.Stat()
		if err != nil || st.IsDir() {
			return errors.New("not a file")
		}
		if off < 0 || off > st.Size() {
			off = 0
		}
		if _, err := file.Seek(off, io.SeekStart); err != nil {
			return err
		}
		if off == 0 {
			h.log("get", arg(f, 1))
		}
		fmt.Fprintf(w, "ok\t%d\n", st.Size())
		io.Copy(w, file)
		return nil

	case "thumb":
		if h.Thumb == nil {
			return errors.New("no thumbnail")
		}
		abs, _, err := h.resolve(arg(f, 1), false, true)
		if err != nil {
			return err
		}
		px, _ := strconv.Atoi(arg(f, 2))
		px = min(max(px, 32), 512)
		img, err := h.Thumb(abs, px)
		if err != nil || len(img) == 0 {
			return errors.New("no thumbnail")
		}
		fmt.Fprintf(w, "ok\t%d\n", len(img))
		_, err = w.Write(img)
		return err

	case "put":
		abs, _, err := h.resolve(arg(f, 1), true, false)
		if err != nil {
			return err
		}
		size, err := strconv.ParseInt(arg(f, 2), 10, 64)
		if err != nil || size < 0 {
			return errors.New("bad size")
		}
		if _, err := os.Lstat(abs); err == nil {
			return errors.New("a file with that name already exists")
		}
		tmp := abs + ".securdp-upload"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		n, err := io.CopyN(out, br, size)
		out.Close()
		if err != nil || n != size {
			os.Remove(tmp)
			return errors.New("upload interrupted")
		}
		if err := os.Rename(tmp, abs); err != nil {
			os.Remove(tmp)
			return err
		}
		h.log("put", arg(f, 1))
		_, err = io.WriteString(w, "ok\n")
		return err

	case "mkdir":
		abs, _, err := h.resolve(arg(f, 1), true, false)
		if err != nil {
			return err
		}
		if err := os.Mkdir(abs, 0o755); err != nil {
			return err
		}
		h.log("mkdir", arg(f, 1))
		_, err = io.WriteString(w, "ok\n")
		return err

	case "delete":
		abs, _, err := h.resolve(arg(f, 1), true, true)
		if err != nil {
			return err
		}
		// Files or empty folders only: no recursive deletes over the tunnel.
		if err := os.Remove(abs); err != nil {
			if st, serr := os.Stat(abs); serr == nil && st.IsDir() {
				return errors.New("folder isn't empty")
			}
			return err
		}
		h.log("delete", arg(f, 1))
		_, err = io.WriteString(w, "ok\n")
		return err

	case "rename":
		from, ff, err := h.resolve(arg(f, 1), true, true)
		if err != nil {
			return err
		}
		to, tf, err := h.resolve(arg(f, 2), true, false)
		if err != nil {
			return err
		}
		if ff.Name != tf.Name {
			return errors.New("can't move between shared folders")
		}
		if _, err := os.Lstat(to); err == nil {
			return errors.New("something with that name already exists")
		}
		if err := os.Rename(from, to); err != nil {
			return err
		}
		h.log("rename", arg(f, 1)+" -> "+arg(f, 2))
		_, err = io.WriteString(w, "ok\n")
		return err
	}
	return errors.New("unknown request")
}

// resolve maps a virtual path to an absolute path inside a granted folder.
// write requires a writable folder; mustExist requires the target to exist
// (otherwise its parent must). The shared folder root itself can be listed
// but never written, renamed or deleted.
func (h *Handler) resolve(vpath string, write, mustExist bool) (string, config.SharedFolder, error) {
	v := path.Clean("/" + strings.ReplaceAll(vpath, `\`, "/"))
	parts := strings.Split(strings.TrimPrefix(v, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", config.SharedFolder{}, errBadPath
	}
	var folder *config.SharedFolder
	for i := range h.Folders {
		if strings.EqualFold(h.Folders[i].Name, parts[0]) {
			folder = &h.Folders[i]
		}
	}
	if folder == nil {
		return "", config.SharedFolder{}, errors.New("no such shared folder")
	}
	rel := parts[1:]
	for _, seg := range rel {
		if !validSegment(seg) {
			return "", *folder, errBadPath
		}
	}
	if write && (!folder.Writable || len(rel) == 0) {
		return "", *folder, errors.New("this folder is read-only")
	}
	abs := filepath.Join(append([]string{folder.Path}, rel...)...)

	root, err := realPath(folder.Path)
	if err != nil {
		return "", *folder, errors.New("shared folder is unavailable")
	}
	check := abs
	if _, err := os.Lstat(abs); err != nil {
		if mustExist {
			return "", *folder, fs.ErrNotExist
		}
		check = filepath.Dir(abs)
	}
	real, err := realPath(check)
	if err != nil || !within(root, real) {
		return "", *folder, errors.New("outside the shared folder")
	}
	return abs, *folder, nil
}

// realPath asks Windows where p really is, following symlinks, junctions and
// mount points (Go's EvalSymlinks no longer follows junctions).
func realPath(p string) (string, error) {
	ptr, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	const fileNameNormalized = 0 // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), fileNameNormalized)
	if err != nil || int(n) >= len(buf) {
		return "", errors.New("can't resolve path")
	}
	s := windows.UTF16ToString(buf[:n])
	if strings.HasPrefix(s, `\\?\UNC\`) {
		return `\\` + s[len(`\\?\UNC\`):], nil
	}
	return strings.TrimPrefix(s, `\\?\`), nil
}

func within(root, p string) bool {
	r, q := strings.ToLower(filepath.Clean(root)), strings.ToLower(filepath.Clean(p))
	return q == r || strings.HasPrefix(q, strings.TrimSuffix(r, `\`)+`\`)
}

var reserved = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$`)

// validSegment rejects names Windows would treat specially (devices,
// alternate data streams, drive letters, trailing dots/spaces).
func validSegment(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 || reserved.MatchString(s) {
		return false
	}
	if strings.ContainsAny(s, `:*?"<>|`) || strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
		return false
	}
	for _, r := range s {
		if r < 32 {
			return false
		}
	}
	return true
}

func hiddenSystem(info fs.FileInfo) bool {
	if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		const hidden, system = 0x2, 0x4
		return d.FileAttributes&hidden != 0 && d.FileAttributes&system != 0
	}
	return false
}

// friendly turns errors into messages that don't reveal local paths.
func friendly(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "not found"
	case errors.Is(err, fs.ErrPermission):
		return "access denied"
	case errors.Is(err, fs.ErrExist):
		return "already exists"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + " failed"
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return "rename failed"
	}
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
