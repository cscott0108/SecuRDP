package gui

import (
	"encoding/json"
	"errors"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	webview2 "github.com/jchv/go-webview2"

	"securdp/internal/config"
)

// RunWeb shows one hub web page (already tunnelled to a loopback address) in
// its own window. Only loopback URLs are accepted, so this can't be used to
// open arbitrary sites.
func RunWeb(title, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.HasPrefix(u.Hostname(), "127.") {
		return errors.New("web: only tunnelled loopback addresses can be opened")
	}
	os.MkdirAll(config.ClientDir(), 0o700)
	// Separate browser profile from the main window; cookies persist per service address.
	w := newWebWindow(title, filepath.Join(config.ClientDir(), "webview-web"))
	if w == nil {
		return errors.New("WebView2 is not available")
	}
	defer w.Destroy()
	w.SetHtml(loadingPage(title, u.String()))
	w.Run()
	return nil
}

// newWebWindow creates the window a hub web page is shown in. Debug is what
// go-webview2 ties the browser's right-click menu (Copy, Paste, Save image…)
// to, so it's on; it also enables F12 / Inspect for troubleshooting pages.
func newWebWindow(title, dataPath string) webview2.WebView {
	width, height := windowSize(1280, 860)
	return webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		DataPath:  dataPath,
		WindowOptions: webview2.WindowOptions{
			Title: "SecuRDP - " + title, Width: width, Height: height, Center: true, IconId: 1,
		},
	})
}

// loadingPage is shown first because WebView2 has no loading indicator of its
// own: it navigates straight on, and stays visible until the real page starts
// arriving, which matters for slow devices like routers.
func loadingPage(title, target string) string {
	t, _ := json.Marshal(target)
	name := html.EscapeString(title)
	return `<!doctype html><html><head><meta charset="utf-8"><style>
html,body{height:100%;margin:0;font:15px "Segoe UI",sans-serif;background:#f4f6f9;color:#1d2430}
@media (prefers-color-scheme:dark){html,body{background:#14171c;color:#e4e8ee}}
.c{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px}
.s{width:34px;height:34px;border:4px solid #2563eb33;border-top-color:#2563eb;border-radius:50%;animation:r .8s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
.bar{position:fixed;top:0;left:0;height:3px;width:30%;background:#2563eb;animation:b 1.4s ease-in-out infinite}
@keyframes b{0%{left:-30%}100%{left:100%}}
</style></head><body><div class="bar"></div><div class="c"><div class="s"></div><div>Loading ` + name + `…</div>
<div style="font-size:12px;opacity:.6">through the SecuRDP tunnel</div></div>
<script>setTimeout(function(){location.replace(` + string(t) + `)},50)</script></body></html>`
}
