package gui

import (
	"errors"
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
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		// Separate browser profile from the main window; cookies persist per service address.
		DataPath: filepath.Join(config.ClientDir(), "webview-web"),
		WindowOptions: webview2.WindowOptions{
			Title: "SecuRDP - " + title, Width: 1280, Height: 860, Center: true, IconId: 1,
		},
	})
	if w == nil {
		return errors.New("WebView2 is not available")
	}
	defer w.Destroy()
	w.Navigate(u.String())
	w.Run()
	return nil
}
