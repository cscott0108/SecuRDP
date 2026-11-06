package gui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadingPageEscapes(t *testing.T) {
	p := loadingPage(`<b>"x"</b>`, `http://127.0.0.11:18080/a?b="c"`)
	if strings.Contains(p, `<b>"x"</b>`) || !strings.Contains(p, `location.replace("http://127.0.0.11:18080/a?b=\"c\"")`) {
		t.Fatal(p)
	}
}

// SECURDP_SLOW_DEMO=1 serves the loading page in front of a 15-second-slow
// page for a minute, to look at it in a browser (prints the URL).
func TestLoadingPageDemo(t *testing.T) {
	if os.Getenv("SECURDP_SLOW_DEMO") == "" {
		t.Skip("set SECURDP_SLOW_DEMO=1")
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/still" { // the loading page alone (navigates only to "#")
			fmt.Fprint(w, loadingPage("router", "#"))
			return
		}
		if r.URL.Path == "/slow" {
			time.Sleep(15 * time.Second)
			fmt.Fprint(w, "<h1>Router admin</h1>")
			return
		}
		fmt.Fprint(w, loadingPage("router", srv.URL+"/slow"))
	}))
	defer srv.Close()
	fmt.Println("DEMO", srv.URL)
	time.Sleep(time.Minute)
}
