package gui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestWebWindowClipboard opens a web window and presses real Ctrl+C / Ctrl+V
// in it. It types only while that window is in front, and puts the clipboard
// text back afterwards. Opt-in: SECURDP_CLIPBOARD_DEMO=1.
func TestWebWindowClipboard(t *testing.T) {
	if os.Getenv("SECURDP_CLIPBOARD_DEMO") == "" {
		t.Skip("set SECURDP_CLIPBOARD_DEMO=1 (opens a window and sends keystrokes to it)")
	}
	saved, _ := clipboardText()
	defer setClipboardText(saved)

	dir, _ := os.MkdirTemp("", "securdp-clip")
	defer os.RemoveAll(dir) // best effort: WebView2 may still hold files
	w := newWebWindow("clipboard test", dir)
	if w == nil {
		t.Fatal("no WebView2")
	}
	defer w.Destroy()
	results := make(chan string, 4)
	w.Bind("report", func(s string) { results <- s })
	// Like a real hub page: the loading page, then navigation to the page;
	// plain page text is selected (not a focused text box).
	page := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		io.WriteString(rw, `<p id=a>copy-me-123</p><textarea id=b></textarea>
<script>onload=()=>{const r=document.createRange();r.selectNodeContents(document.getElementById('a'));getSelection().addRange(r);report('ready')}</script>`)
	}))
	defer page.Close()
	w.SetHtml(loadingPage("clipboard test", page.URL+"/"))
	hwnd := uintptr(w.Window())
	go func() {
		<-results // ready
		time.Sleep(700 * time.Millisecond)
		fg, _, _ := procGetForegroundWindow.Call()
		if fg != hwnd {
			results <- "SKIP: the test window isn't in front"
			w.Dispatch(w.Terminate)
			return
		}
		ctrlKey('C')
		time.Sleep(500 * time.Millisecond)
		copied, _ := clipboardText()
		setClipboardText("pasted-ok")
		w.Dispatch(func() { w.Eval(`document.getElementById('b').focus()`) })
		time.Sleep(300 * time.Millisecond)
		if fg, _, _ := procGetForegroundWindow.Call(); fg == hwnd {
			ctrlKey('V')
		}
		time.Sleep(500 * time.Millisecond)
		w.Dispatch(func() { w.Eval(`report('copied=` + copied + ` pasted='+document.getElementById('b').value)`) })
		time.Sleep(300 * time.Millisecond)
		w.Dispatch(w.Terminate)
	}()
	w.Run()
	select {
	case r := <-results:
		t.Log(r)
		if r != "copied=copy-me-123 pasted=pasted-ok" {
			t.Errorf("clipboard keys don't work: %s", r)
		}
	default:
		t.Fatal("no result")
	}
}

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procKeybdEvent          = user32.NewProc("keybd_event")
	procOpenClipboard       = user32.NewProc("OpenClipboard")
	procCloseClipboard      = user32.NewProc("CloseClipboard")
	procEmptyClipboard      = user32.NewProc("EmptyClipboard")
	procGetClipboardData    = user32.NewProc("GetClipboardData")
	procSetClipboardData    = user32.NewProc("SetClipboardData")
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalAlloc         = kernel32.NewProc("GlobalAlloc")
	procGlobalLock          = kernel32.NewProc("GlobalLock")
	procGlobalUnlock        = kernel32.NewProc("GlobalUnlock")
)

func ctrlKey(vk byte) {
	const ctrl, up = 0x11, 2
	procKeybdEvent.Call(ctrl, 0, 0, 0)
	procKeybdEvent.Call(uintptr(vk), 0, 0, 0)
	procKeybdEvent.Call(uintptr(vk), 0, up, 0)
	procKeybdEvent.Call(ctrl, 0, up, 0)
}

const cfUnicodeText = 13

func clipboardText() (string, bool) {
	if r, _, _ := procOpenClipboard.Call(0); r == 0 {
		return "", false
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", false
	}
	p, _, _ := procGlobalLock.Call(h)
	defer procGlobalUnlock.Call(h)
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(p))), true
}

func setClipboardText(s string) {
	if r, _, _ := procOpenClipboard.Call(0); r == 0 {
		return
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	u, _ := windows.UTF16FromString(s)
	h, _, _ := procGlobalAlloc.Call(0x0002, uintptr(len(u)*2)) // GMEM_MOVEABLE
	p, _, _ := procGlobalLock.Call(h)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(p)), len(u)), u)
	procGlobalUnlock.Call(h)
	procSetClipboardData.Call(cfUnicodeText, h)
}
