package gui

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32dll                = windows.NewLazySystemDLL("user32.dll")
	procGetDpiForSystem      = user32dll.NewProc("GetDpiForSystem")
	procSystemParametersInfo = user32dll.NewProc("SystemParametersInfoW")
)

// windowSize turns a window size designed for 100% display scaling into
// pixels for this display. The exe is per-monitor DPI aware (tools/mkres), so
// sizes are real pixels: without this a window opens at half size on a 200%
// screen. It is kept within 90% of the screen's work area.
func windowSize(w, h uint) (uint, uint) {
	dpi := uint(96)
	if procGetDpiForSystem.Find() == nil {
		if d, _, _ := procGetDpiForSystem.Call(); d >= 96 {
			dpi = uint(d)
		}
	}
	w, h = w*dpi/96, h*dpi/96
	var work struct{ Left, Top, Right, Bottom int32 }
	const spiGetWorkArea = 0x0030
	if r, _, _ := procSystemParametersInfo.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&work)), 0); r != 0 {
		if maxW := uint(work.Right-work.Left) * 9 / 10; maxW > 0 && w > maxW {
			w = maxW
		}
		if maxH := uint(work.Bottom-work.Top) * 9 / 10; maxH > 0 && h > maxH {
			h = maxH
		}
	}
	return w, h
}
