// Package thumb makes file thumbnails with the Windows Shell (the same
// thumbnails Explorer shows, including video frames), falling back to Go's
// image decoders for common image formats.
package thumb

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	_ "image/gif"
	_ "image/png"

	"golang.org/x/sys/windows"
)

var (
	ole32   = windows.NewLazySystemDLL("ole32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")
	gdi32   = windows.NewLazySystemDLL("gdi32.dll")

	pCoInitializeEx              = ole32.NewProc("CoInitializeEx")
	pSHCreateItemFromParsingName = shell32.NewProc("SHCreateItemFromParsingName")
	pGetObject                   = gdi32.NewProc("GetObjectW")
	pGetDIBits                   = gdi32.NewProc("GetDIBits")
	pCreateCompatibleDC          = gdi32.NewProc("CreateCompatibleDC")
	pDeleteDC                    = gdi32.NewProc("DeleteDC")
	pDeleteObject                = gdi32.NewProc("DeleteObject")

	iidImageFactory = windows.GUID{Data1: 0xbcc18b79, Data2: 0xba16, Data3: 0x442f,
		Data4: [8]byte{0x80, 0xc4, 0x8a, 0x59, 0xc3, 0x0c, 0x46, 0x3b}}
)

// Kinds that get thumbnails; everything else gets an icon on the client.
var mediaExt = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".webp": true, ".heic": true,
	".tif": true, ".tiff": true, ".mp4": true, ".m4v": true, ".mov": true, ".mkv": true, ".avi": true,
	".wmv": true, ".webm": true, ".mpg": true, ".mpeg": true, ".3gp": true, ".ts": true,
}

// HasThumbnail reports whether name is an image or video type.
func HasThumbnail(name string) bool { return mediaExt[strings.ToLower(filepath.Ext(name))] }

type job struct {
	path string
	px   int
	res  chan result
}
type result struct {
	img image.Image
	err error
}

var jobs = make(chan job)

// The Shell's COM objects need a single-threaded apartment, so all shell
// work happens on one locked OS thread.
func init() {
	go func() {
		runtime.LockOSThread()
		pCoInitializeEx.Call(0, 0x2) // COINIT_APARTMENTTHREADED
		for j := range jobs {
			img, err := shellThumb(j.path, j.px)
			j.res <- result{img, err}
		}
	}()
}

// Get returns a JPEG thumbnail no larger than px on its longest side.
func Get(path string, px int) ([]byte, error) {
	if !HasThumbnail(path) {
		return nil, errors.New("not an image or video")
	}
	res := make(chan result, 1)
	jobs <- job{path, px, res}
	r := <-res
	img := r.img
	if r.err != nil || img == nil {
		var err error
		if img, err = decodeImage(path, px); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func shellThumb(path string, px int) (image.Image, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// A COM object is a pointer to its vtable: QueryInterface, AddRef, Release, GetImage.
	var factory *struct{ vtbl *[4]uintptr }
	hr, _, _ := pSHCreateItemFromParsingName.Call(uintptr(unsafe.Pointer(p)), 0,
		uintptr(unsafe.Pointer(&iidImageFactory)), uintptr(unsafe.Pointer(&factory)))
	if hr != 0 || factory == nil {
		return nil, errors.New("shell item failed")
	}
	vtbl := factory.vtbl
	defer syscallN(vtbl[2], uintptr(unsafe.Pointer(factory))) // Release

	// IShellItemImageFactory::GetImage(SIZE, SIIGBF, HBITMAP*); SIZE fits in one register.
	size := uintptr(uint32(px)) | uintptr(uint32(px))<<32
	const thumbnailOnly = 0x8
	var hbm uintptr
	if r := syscallN(vtbl[3], uintptr(unsafe.Pointer(factory)), size, thumbnailOnly, uintptr(unsafe.Pointer(&hbm))); r != 0 || hbm == 0 {
		return nil, errors.New("no shell thumbnail")
	}
	defer pDeleteObject.Call(hbm)
	return bitmapToImage(hbm)
}

func syscallN(fn uintptr, args ...uintptr) uintptr {
	r, _, _ := syscallNRaw(fn, args...)
	return r
}

type bitmap struct {
	Type, Width, Height, WidthBytes int32
	Planes, BitsPixel               uint16
	Bits                            uintptr
}

type bitmapInfoHeader struct {
	Size                         uint32
	Width, Height                int32
	Planes, BitCount             uint16
	Compression, SizeImage       uint32
	XPelsPerMeter, YPelsPerMeter int32
	ClrUsed, ClrImportant        uint32
}

func bitmapToImage(hbm uintptr) (image.Image, error) {
	var bm bitmap
	if r, _, _ := pGetObject.Call(hbm, unsafe.Sizeof(bm), uintptr(unsafe.Pointer(&bm))); r == 0 || bm.Width <= 0 || bm.Height <= 0 {
		return nil, errors.New("bad bitmap")
	}
	w, h := int(bm.Width), int(bm.Height)
	bih := bitmapInfoHeader{Size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}
	buf := make([]byte, w*h*4)
	dc, _, _ := pCreateCompatibleDC.Call(0)
	defer pDeleteDC.Call(dc)
	if r, _, _ := pGetDIBits.Call(dc, hbm, 0, uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bih)), 0); r == 0 {
		return nil, errors.New("GetDIBits failed")
	}
	// BGRA; alpha is either all zero (opaque) or premultiplied.
	hasAlpha := false
	for i := 3; i < len(buf); i += 4 {
		if buf[i] != 0 {
			hasAlpha = true
			break
		}
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		b, g, r, a := buf[i*4], buf[i*4+1], buf[i*4+2], buf[i*4+3]
		if hasAlpha && a < 255 { // composite premultiplied pixels over white
			inv := 255 - uint32(a)
			r, g, b = uint8(uint32(r)+inv), uint8(uint32(g)+inv), uint8(uint32(b)+inv)
		}
		img.Pix[i*4], img.Pix[i*4+1], img.Pix[i*4+2], img.Pix[i*4+3] = r, g, b, 255
	}
	return img, nil
}

// decodeImage is the fallback for JPEG/PNG/GIF when the shell has no thumbnail.
func decodeImage(path string, px int) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > 64<<20 {
		return nil, errors.New("too large to decode")
	}
	src, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}
	return shrink(src, px), nil
}

// shrink box-filters src to fit within px x px (never enlarges).
func shrink(src image.Image, px int) image.Image {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= px && sh <= px {
		return src
	}
	scale := float64(px) / float64(max(sw, sh))
	dw, dh := max(1, int(float64(sw)*scale)), max(1, int(float64(sh)*scale))
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < dh; y++ {
		y0, y1 := b.Min.Y+y*sh/dh, b.Min.Y+max((y+1)*sh/dh, y*sh/dh+1)
		for x := 0; x < dw; x++ {
			x0, x1 := b.Min.X+x*sw/dw, b.Min.X+max((x+1)*sw/dw, x*sw/dw+1)
			var r, g, bl, n uint32
			for yy := y0; yy < y1; yy += max(1, (y1-y0)/4) {
				for xx := x0; xx < x1; xx += max(1, (x1-x0)/4) {
					cr, cg, cb, _ := src.At(xx, yy).RGBA()
					r, g, bl, n = r+cr, g+cg, bl+cb, n+1
				}
			}
			dst.Set(x, y, color.RGBA{uint8(r / n >> 8), uint8(g / n >> 8), uint8(bl / n >> 8), 255})
		}
	}
	return dst
}
