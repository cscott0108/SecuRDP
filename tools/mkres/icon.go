package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// The SecuRDP icon: a blue shield with a white padlock, drawn from shapes in
// normalized [0,1] coordinates so it renders crisply at any size.

func shield(x, y float64) bool {
	const top, bottom, half = 0.06, 0.96, 0.41
	if y < top || y > bottom {
		return false
	}
	dx := math.Abs(x - 0.5)
	if y < top+0.05*(1-math.Pow(dx/half, 2)) { // gently dipped top edge
		return false
	}
	w := half
	if y > 0.52 {
		t := (y - 0.52) / (bottom - 0.52)
		w = half * math.Sqrt(1-t*t)
	}
	return dx <= w
}

func roundRect(x, y, x0, y0, x1, y1, r float64) bool {
	if x < x0 || x > x1 || y < y0 || y > y1 {
		return false
	}
	cx := math.Max(x0+r, math.Min(x, x1-r))
	cy := math.Max(y0+r, math.Min(y, y1-r))
	return math.Hypot(x-cx, y-cy) <= r
}

func lock(x, y float64) bool {
	const cx, by0 = 0.5, 0.47
	if roundRect(x, y, cx-0.19, by0, cx+0.19, 0.78, 0.035) {
		return true
	}
	d := math.Hypot(x-cx, y-by0)
	return y <= by0 && d <= 0.145 && d >= 0.09
}

func keyhole(x, y float64) bool {
	if math.Hypot(x-0.5, y-0.585) <= 0.04 {
		return true
	}
	return math.Abs(x-0.5) <= 0.018 && y >= 0.585 && y <= 0.69
}

func lerp(a, b uint8, t float64) float64 { return float64(a) + (float64(b)-float64(a))*t }

// renderIcon draws the icon filling a size x size image.
func renderIcon(size int) *image.NRGBA { return renderIconScaled(size, 1) }

// renderIconScaled draws the icon shrunk to `scale` of the canvas, centred
// (Android adaptive icons need the artwork inside the middle ~60%).
func renderIconScaled(size int, scale float64) *image.NRGBA {
	ss := 4
	if size <= 48 {
		ss = 8
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	top := color.NRGBA{0x3b, 0x82, 0xf6, 0xff} // blue-500
	bot := color.NRGBA{0x1e, 0x3a, 0x8a, 0xff} // blue-900
	n := float64(ss * ss)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px)+(float64(sx)+0.5)/float64(ss))/float64(size)/scale + 0.5 - 0.5/scale
					y := (float64(py)+(float64(sy)+0.5)/float64(ss))/float64(size)/scale + 0.5 - 0.5/scale
					if !shield(x, y) {
						continue
					}
					if lock(x, y) && !keyhole(x, y) {
						r, g, b = r+255, g+255, b+255
					} else {
						t := (y - 0.06) / 0.9
						r += lerp(top.R, bot.R, t)
						g += lerp(top.G, bot.G, t)
						b += lerp(top.B, bot.B, t)
					}
					a++
				}
			}
			if a > 0 {
				img.SetNRGBA(px, py, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(255 * a / n)})
			}
		}
	}
	return img
}

func pngBytes(img image.Image) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
