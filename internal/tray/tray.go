// Package tray shows the SecuRDP notification-area icon on server PCs. It
// uses the Win32 API directly (no extra dependencies).
package tray

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"securdp/internal/service"
	"securdp/internal/winutil"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassEx         = user32.NewProc("RegisterClassExW")
	pCreateWindowEx          = user32.NewProc("CreateWindowExW")
	pDefWindowProc           = user32.NewProc("DefWindowProcW")
	pGetMessage              = user32.NewProc("GetMessageW")
	pTranslateMessage        = user32.NewProc("TranslateMessage")
	pDispatchMessage         = user32.NewProc("DispatchMessageW")
	pPostQuitMessage         = user32.NewProc("PostQuitMessage")
	pDestroyWindow           = user32.NewProc("DestroyWindow")
	pCreatePopupMenu         = user32.NewProc("CreatePopupMenu")
	pAppendMenu              = user32.NewProc("AppendMenuW")
	pSetMenuDefaultItem      = user32.NewProc("SetMenuDefaultItem")
	pTrackPopupMenu          = user32.NewProc("TrackPopupMenu")
	pDestroyMenu             = user32.NewProc("DestroyMenu")
	pSetForegroundWindow     = user32.NewProc("SetForegroundWindow")
	pGetCursorPos            = user32.NewProc("GetCursorPos")
	pLoadImage               = user32.NewProc("LoadImageW")
	pGetSystemMetrics        = user32.NewProc("GetSystemMetrics")
	pSetTimer                = user32.NewProc("SetTimer")
	pRegisterWindowMessage   = user32.NewProc("RegisterWindowMessageW")
	pFindWindow              = user32.NewProc("FindWindowW")
	pPostMessage             = user32.NewProc("PostMessageW")
	pShowWindow              = user32.NewProc("ShowWindow")
	pIsIconic                = user32.NewProc("IsIconic")
	pShellNotifyIcon         = shell32.NewProc("Shell_NotifyIconW")
	pGetModuleHandle         = kernel32.NewProc("GetModuleHandleW")
	pAllowSetForegroundWindw = user32.NewProc("AllowSetForegroundWindow")
)

const (
	className = "SecuRDPTray"

	wmDestroy     = 0x0002
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wmTimer       = 0x0113
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmTrayMessage = 0x8000 + 1 // WM_APP + 1

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2
	nifMsg    = 0x1
	nifIcon   = 0x2
	nifTip    = 0x4

	mfString    = 0x0
	mfGrayed    = 0x1
	mfSeparator = 0x800
	tpmReturn   = 0x100
	tpmRight    = 0x2

	cmdOpen = iota + 100
	cmdOpenAdmin
	cmdHide
)

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type msg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
	Private uint32
}

type tray struct {
	hwnd           uintptr
	nid            notifyIconData
	taskbarCreated uint32
	status         string
}

var t tray

func u16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

// Run shows the tray icon until "Hide tray icon" is chosen or the service is
// uninstalled. A newer instance replaces an older one in the same session.
func Run() error {
	runtime.LockOSThread()

	// Replace an already-running tray (e.g. the old binary after an update).
	if old, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(u16(className))), 0); old != 0 {
		pPostMessage.Call(old, wmClose, 0, 0)
		for i := 0; i < 20; i++ {
			time.Sleep(100 * time.Millisecond)
			if h, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(u16(className))), 0); h == 0 {
				break
			}
		}
	}

	hinst, _, _ := pGetModuleHandle.Call(0)
	wc := wndClassEx{
		LpfnWndProc:   windows.NewCallback(wndProc),
		HInstance:     hinst,
		LpszClassName: u16(className),
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	if r, _, err := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return err
	}
	// A hidden top-level window (never shown) so we receive "TaskbarCreated"
	// when Explorer restarts and can re-add the icon.
	hwnd, _, err := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(u16(className))),
		uintptr(unsafe.Pointer(u16("SecuRDP tray"))), 0, 0, 0, 0, 0, 0, 0, hinst, 0)
	if hwnd == 0 {
		return err
	}
	t.hwnd = hwnd
	tc, _, _ := pRegisterWindowMessage.Call(uintptr(unsafe.Pointer(u16("TaskbarCreated"))))
	t.taskbarCreated = uint32(tc)

	cx, _, _ := pGetSystemMetrics.Call(49) // SM_CXSMICON
	cy, _, _ := pGetSystemMetrics.Call(50)
	icon, _, _ := pLoadImage.Call(hinst, 1, 1 /*IMAGE_ICON*/, cx, cy, 0)

	t.nid = notifyIconData{HWnd: hwnd, UID: 1, UFlags: nifMsg | nifIcon | nifTip,
		UCallbackMessage: wmTrayMessage, HIcon: icon}
	t.nid.CbSize = uint32(unsafe.Sizeof(t.nid))
	t.refresh()
	pShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid)))
	pSetTimer.Call(hwnd, 1, 5000, 0)

	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}

// refresh updates the tooltip from the service state. Returns false once the
// service has been uninstalled.
func (t *tray) refresh() bool {
	t.status = service.Status()
	tip := "SecuRDP - gate " + t.status
	if t.status == "running" {
		tip = "SecuRDP - gate running"
	}
	s, _ := windows.UTF16FromString(tip)
	copy(t.nid.SzTip[:len(t.nid.SzTip)-1], s)
	return t.status != "not installed"
}

func wndProc(hwnd uintptr, m uint32, wp, lp uintptr) uintptr {
	switch {
	case m == wmTrayMessage:
		switch lp {
		case wmLButtonDbl, wmLButtonUp:
			openUI(false)
		case wmRButtonUp:
			showMenu(hwnd)
		}
		return 0
	case m == wmTimer:
		if !t.refresh() {
			pDestroyWindow.Call(hwnd)
			return 0
		}
		pShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
		return 0
	case m == wmCommand:
		switch wp & 0xffff {
		case cmdOpen:
			openUI(false)
		case cmdOpenAdmin:
			openUI(true)
		case cmdHide:
			pDestroyWindow.Call(hwnd)
		}
		return 0
	case m == wmClose:
		pDestroyWindow.Call(hwnd)
		return 0
	case m == wmDestroy:
		pShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
		pPostQuitMessage.Call(0)
		return 0
	case t.taskbarCreated != 0 && m == t.taskbarCreated:
		pShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid)))
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, uintptr(m), wp, lp)
	return r
}

func showMenu(hwnd uintptr) {
	menu, _, _ := pCreatePopupMenu.Call()
	defer pDestroyMenu.Call(menu)
	add := func(flags, id uintptr, text string) {
		pAppendMenu.Call(menu, flags, id, uintptr(unsafe.Pointer(u16(text))))
	}
	add(mfString, cmdOpen, "Open SecuRDP")
	add(mfString, cmdOpenAdmin, "Open as administrator (server settings)")
	add(mfSeparator, 0, "")
	add(mfString|mfGrayed, 0, "Gate service: "+t.status)
	add(mfSeparator, 0, "")
	add(mfString, cmdHide, "Hide tray icon (until next sign-in)")
	pSetMenuDefaultItem.Call(menu, cmdOpen, 0)

	var pt struct{ X, Y int32 }
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(hwnd) // required so the menu closes when clicking elsewhere
	cmd, _, _ := pTrackPopupMenu.Call(menu, tpmReturn|tpmRight, uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
	if cmd != 0 {
		pPostMessage.Call(hwnd, wmCommand, cmd, 0)
	}
}

// openUI focuses an existing SecuRDP window, or starts a new one.
func openUI(admin bool) {
	if !admin {
		if FocusExistingWindow() {
			return
		}
	}
	if admin {
		winutil.RelaunchElevated("gui")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "gui")
	// CREATE_NO_WINDOW only: HideWindow would also hide the app's main window.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	if cmd.Start() != nil {
		return
	}
	pAllowSetForegroundWindw.Call(uintptr(cmd.Process.Pid))
}

// IsRunning reports whether a tray icon is already running in this session.
func IsRunning() bool {
	h, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(u16(className))), 0)
	return h != 0
}

// StartIfNeeded starts the installed tray (no console window) on a server PC
// where it isn't running yet, e.g. right after first install.
func StartIfNeeded() {
	if IsRunning() || service.Status() == "not installed" {
		return
	}
	exe := service.InstalledExe()
	if _, err := os.Stat(exe); err != nil {
		return
	}
	cmd := exec.Command(exe, "tray")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00000008} // NO_WINDOW | DETACHED
	cmd.Start()
}

// showEvent is signalled to ask an open SecuRDP window to show itself. The
// window does its own restore/focus, which works even when it runs elevated
// and the requester doesn't (Windows blocks most cross-integrity window calls).
const showEvent = `Local\SecuRDPShowWindow`

// FocusExistingWindow asks an open SecuRDP window to come to the front.
// The app window is go-webview2's "webview" class titled "SecuRDP" or
// "SecuRDP (Administrator)".
func FocusExistingWindow() bool {
	var h uintptr
	for _, title := range []string{"SecuRDP (Administrator)", "SecuRDP"} {
		if h, _, _ = pFindWindow.Call(uintptr(unsafe.Pointer(u16("webview"))), uintptr(unsafe.Pointer(u16(title)))); h != 0 {
			break
		}
	}
	if h == 0 {
		return false
	}
	pAllowSetForegroundWindw.Call(0xFFFFFFFF) // ASFW_ANY: let that window take focus
	ev, err := windows.OpenEvent(0x0002 /*EVENT_MODIFY_STATE*/, false, u16(showEvent))
	if err != nil {
		return false // a window without the listener (older version): open a new one
	}
	windows.SetEvent(ev)
	windows.CloseHandle(ev)
	return true
}

// ServeShowRequests runs in the GUI process: whenever FocusExistingWindow
// signals, it restores and focuses hwnd.
func ServeShowRequests(hwnd uintptr) {
	// Any signed-in user may signal (medium integrity label), so a
	// non-elevated tray can reach an elevated window.
	sd, err := windows.SecurityDescriptorFromString("D:(A;;0x1F0003;;;AU)S:(ML;;NW;;;ME)")
	if err != nil {
		return
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	ev, err := windows.CreateEvent(&sa, 0, 0, u16(showEvent))
	if ev == 0 {
		return // ERROR_ALREADY_EXISTS still returns a usable handle
	}
	_ = err
	for {
		if r, _ := windows.WaitForSingleObject(ev, windows.INFINITE); r != windows.WAIT_OBJECT_0 {
			return
		}
		if ic, _, _ := pIsIconic.Call(hwnd); ic != 0 {
			pShowWindow.Call(hwnd, 9) // SW_RESTORE
		} else {
			pShowWindow.Call(hwnd, 5) // SW_SHOW
		}
		pSetForegroundWindow.Call(hwnd)
	}
}
