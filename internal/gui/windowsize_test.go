package gui

import (
	"testing"
	"unsafe"
)

func TestWindowSizeFollowsScaling(t *testing.T) {
	// Like the real exe (its manifest says PerMonitorV2).
	user32dll.NewProc("SetProcessDpiAwarenessContext").Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	d, _, _ := procGetDpiForSystem.Call()
	var work struct{ Left, Top, Right, Bottom int32 }
	procSystemParametersInfo.Call(0x0030, 0, uintptr(unsafe.Pointer(&work)), 0)
	sw, sh := uint(work.Right-work.Left), uint(work.Bottom-work.Top)

	w, h := windowSize(1100, 820)
	t.Logf("scaling %d%%, work area %dx%d: 1100x820 opens as %dx%d", d*100/96, sw, sh, w, h)
	// Full design size at this scaling, unless the screen is too small for it.
	wantW, wantH := min(1100*uint(d)/96, sw*9/10), min(820*uint(d)/96, sh*9/10)
	if w != wantW || h != wantH {
		t.Fatalf("got %dx%d, want %dx%d", w, h, wantW, wantH)
	}
}
