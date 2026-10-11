package geo

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// The lookup runs through whatever dialer it is given, which is how the
// pipeline points it at a proxy tunnel.
func TestExitIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ip":
			w.Write([]byte("203.0.113.7\n"))
		case "/junk":
			w.Write([]byte("<html>captive portal</html>"))
		default:
			http.Error(w, "nope", http.StatusBadGateway)
		}
	}))
	defer srv.Close()

	restore := EchoURL
	defer func() { EchoURL = restore }()

	EchoURL = srv.URL + "/ip"
	addr, err := ExitIP(context.Background(), &net.Dialer{})
	if err != nil {
		t.Fatalf("ExitIP: %v", err)
	}
	if addr.String() != "203.0.113.7" {
		t.Errorf("ExitIP = %s, want 203.0.113.7", addr)
	}

	EchoURL = srv.URL + "/junk"
	if addr, err := ExitIP(context.Background(), &net.Dialer{}); err == nil {
		t.Errorf("ExitIP accepted junk and returned %s", addr)
	}

	EchoURL = srv.URL + "/error"
	if _, err := ExitIP(context.Background(), &net.Dialer{}); err == nil {
		t.Error("ExitIP accepted a 502 response")
	}
}

// A proxy that refuses CONNECT still forwards absolute-URI requests, and that
// is the only way the lookup can reach the echo endpoint through it.
func TestExitIPForward(t *testing.T) {
	const echo = "http://echo.test/ip" // never resolved: the request goes to the proxy
	var connects atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connects.Add(1)
			http.Error(w, "no tunnels here", http.StatusMethodNotAllowed)
			return
		}
		if r.RequestURI != echo {
			http.Error(w, "not an absolute-URI request: "+r.RequestURI, http.StatusBadRequest)
			return
		}
		w.Write([]byte("203.0.113.9\n"))
	}))
	defer proxy.Close()

	restore := PlainEchoURL
	defer func() { PlainEchoURL = restore }()
	PlainEchoURL = echo

	addr, err := ExitIPForward(context.Background(), &net.Dialer{}, proxy.Listener.Addr().String())
	if err != nil {
		t.Fatalf("ExitIPForward: %v", err)
	}
	if addr.String() != "203.0.113.9" {
		t.Errorf("ExitIPForward = %s, want 203.0.113.9", addr)
	}
	if n := connects.Load(); n != 0 {
		t.Errorf("%d CONNECT requests sent; the proxy forwards only", n)
	}
}
