package thumb

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestThumbnailOfPNG(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 800, 400))
	for y := 0; y < 400; y++ {
		for x := 0; x < 800; x++ {
			src.Set(x, y, color.RGBA{uint8(x / 4), 0, 200, 255})
		}
	}
	p := filepath.Join(t.TempDir(), "pic.png")
	f, _ := os.Create(p)
	png.Encode(f, src)
	f.Close()

	b, err := Get(p, 128)
	if err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if w, h := img.Bounds().Dx(), img.Bounds().Dy(); w > 128 || h > 128 || w < 32 {
		t.Fatalf("thumbnail size %dx%d", w, h)
	}
	if _, err := Get(filepath.Join(t.TempDir(), "notes.txt"), 128); err == nil {
		t.Fatal("thumbnail for a text file")
	}
}

// The Windows Shell path (used for videos) must work, not just the fallback.
// SECURDP_THUMB_VIDEO=<path to a video> also checks a video frame.
func TestShellThumbnail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pic.png")
	f, _ := os.Create(p)
	png.Encode(f, image.NewRGBA(image.Rect(0, 0, 300, 300)))
	f.Close()
	paths := []string{p}
	if v := os.Getenv("SECURDP_THUMB_VIDEO"); v != "" {
		paths = append(paths, v)
	}
	for _, path := range paths {
		res := make(chan result, 1)
		jobs <- job{path, 128, res}
		if r := <-res; r.err != nil || r.img == nil {
			t.Fatalf("shell thumbnail for %s: %v", filepath.Base(path), r.err)
		} else {
			t.Logf("shell thumbnail for %s: %v", filepath.Base(path), r.img.Bounds())
		}
	}
}

func TestShrinkKeepsAspect(t *testing.T) {
	img := shrink(image.NewRGBA(image.Rect(0, 0, 1000, 500)), 100)
	if img.Bounds().Dx() != 100 || img.Bounds().Dy() != 50 {
		t.Fatal(img.Bounds())
	}
}
