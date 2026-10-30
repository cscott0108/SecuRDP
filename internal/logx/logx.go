// Package logx is a tiny size-rotated file logger for the service.
package logx

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const maxSize = 5 << 20

type Logger struct {
	mu   sync.Mutex
	path string
	f    *os.File
	tee  io.Writer
}

func Open(path string, tee io.Writer) (*Logger, error) {
	l := &Logger{path: path, tee: tee}
	return l, l.reopen()
}

func (l *Logger) reopen() error {
	if l.f != nil {
		l.f.Close()
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.f = f
	return nil
}

func (l *Logger) Printf(format string, args ...any) {
	line := time.Now().Format("2006-01-02 15:04:05") + "  " + fmt.Sprintf(format, args...) + "\n"
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tee != nil {
		io.WriteString(l.tee, line)
	}
	if l.f == nil {
		return
	}
	if st, err := l.f.Stat(); err == nil && st.Size() > maxSize {
		l.f.Close()
		os.Rename(l.path, l.path+".1")
		l.f = nil
		if l.reopen() != nil {
			return
		}
	}
	l.f.WriteString(line)
}

// Tail returns roughly the last n bytes of the log file.
func Tail(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := st.Size() - n
	if off < 0 {
		off = 0
	}
	f.Seek(off, io.SeekStart)
	b, _ := io.ReadAll(f)
	return string(b)
}
