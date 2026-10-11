package xray

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	"shimmer/internal/dial"
	"shimmer/internal/geo"
	"shimmer/internal/link"
	"shimmer/internal/probe"
)

const testID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// check204 serves the check endpoint: 204 on every request.
func check204(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// freePort finds a port nothing listens on, for TCP or UDP.
func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// server starts an Xray server with one inbound, described by its JSON, and
// a direct outbound.
func server(t *testing.T, inbound string) {
	t.Helper()
	cfg, err := serial.LoadJSONConfig(strings.NewReader(`{
		"log": {"loglevel": "none"},
		"inbounds": [` + inbound + `],
		"outbounds": [{"protocol": "freedom", "tag": "direct"}]
	}`))
	if err != nil {
		t.Fatalf("server config: %v", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
}

func engine(t *testing.T) *Engine {
	t.Helper()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func parse(t *testing.T, s string) *link.Link {
	t.Helper()
	l, err := link.Parse(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return l
}

// get asks target for "/" through the tunnel and returns the status code.
func get(ctx context.Context, tun dial.Tunnel, target string) (int, error) {
	c, err := tun.DialContext(ctx, "tcp", target)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+target+"\r\nConnection: close\r\n\r\n"); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func selfSigned(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	c, _ := cert.MustGenerate(nil, cert.DNSNames("test.local"), cert.CommonName("test.local"))
	certB, keyB := c.ToPEM()
	return string(certB), string(keyB)
}

func pemLines(s string) string {
	var quoted []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		quoted = append(quoted, fmt.Sprintf("%q", l))
	}
	return strings.Join(quoted, ",")
}

func TestProtocols(t *testing.T) {
	target := check204(t)
	e := engine(t)
	certPEM, keyPEM := selfSigned(t)
	certs := `"certificates": [{"certificate": [` + pemLines(certPEM) + `], "key": [` + pemLines(keyPEM) + `]}]`
	tlsInbound := `"security": "tls", "tlsSettings": {` + certs + `}`
	quicInbound := `"security": "tls", "tlsSettings": {"alpn": ["h3"], ` + certs + `}`

	cases := []struct {
		name    string
		inbound func(port int) string
		link    func(port int) string
		udp     bool
	}{
		{
			name: "vless raw",
			inbound: func(port int) string {
				return fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
					"settings": {"clients": [{"id": %q}], "decryption": "none"}}`, port, testID)
			},
			link: func(port int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?encryption=none&security=none&type=tcp#a%%20name", testID, port)
			},
		},
		{
			name: "vmess ws",
			inbound: func(port int) string {
				return fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "vmess",
					"settings": {"clients": [{"id": %q}]},
					"streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}`, port, testID)
			},
			link: func(port int) string {
				return fmt.Sprintf("vmess://%s@127.0.0.1:%d?encryption=auto&security=none&type=ws&path=/ws", testID, port)
			},
		},
		{
			name: "trojan grpc",
			inbound: func(port int) string {
				return fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "trojan",
					"settings": {"clients": [{"password": "secret"}]},
					"streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "svc"}}}`, port)
			},
			link: func(port int) string {
				return fmt.Sprintf("trojan://secret@127.0.0.1:%d?security=none&type=grpc&serviceName=svc", port)
			},
		},
		{
			name: "shadowsocks",
			inbound: func(port int) string {
				return fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "shadowsocks",
					"settings": {"method": "aes-128-gcm", "password": "pass", "network": "tcp"}}`, port)
			},
			link: func(port int) string {
				return fmt.Sprintf("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:%d#ss", port) // aes-128-gcm:pass
			},
		},
		{
			name: "vless tls insecure",
			inbound: func(port int) string {
				return fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
					"settings": {"clients": [{"id": %q}], "decryption": "none"},
					"streamSettings": {"network": "raw", %s}}`, port, testID, tlsInbound)
			},
			link: func(port int) string {
				return fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=test.local&allowInsecure=1&type=tcp", testID, port)
			},
		},
		{
			name: "hysteria2",
			udp:  true,
			inbound: func(port int) string {
				return fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "hysteria",
					"settings": {"version": 2, "clients": [{"auth": "hy-pass"}]},
					"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, %s}}`, port, quicInbound)
			},
			link: func(port int) string {
				return fmt.Sprintf("hy2://hy-pass@127.0.0.1:%d/?sni=test.local&insecure=1#hy", port)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			network := "tcp"
			if tc.udp {
				network = "udp"
			}
			port := freePort(t, network)
			server(t, tc.inbound(port))

			tun, err := e.Open(context.Background(), parse(t, tc.link(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer tun.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			code, err := get(ctx, tun, target)
			if err != nil {
				t.Fatalf("through the link: %v", err)
			}
			if code != 204 {
				t.Fatalf("got %d through the link, want 204", code)
			}
		})
	}
}

// Without insecure, a self-signed server must fail verification: otherwise
// the insecure test above proves nothing.
func TestVerifiesCertificate(t *testing.T) {
	target := check204(t)
	e := engine(t)
	certPEM, keyPEM := selfSigned(t)
	port := freePort(t, "tcp")
	server(t, fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
		"settings": {"clients": [{"id": %q}], "decryption": "none"},
		"streamSettings": {"security": "tls", "tlsSettings": {"certificates": [{"certificate": [%s], "key": [%s]}]}}}`,
		port, testID, pemLines(certPEM), pemLines(keyPEM)))

	tun, err := e.Open(context.Background(), parse(t, fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=test.local", testID, port)))
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := get(ctx, tun, target); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("got %v, want a certificate error", err)
	}
}

func TestDeadServerReason(t *testing.T) {
	e := engine(t)
	port := freePort(t, "tcp") // nothing listens here
	tun, err := e.Open(context.Background(), parse(t, fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none", testID, port)))
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = get(ctx, tun, "127.0.0.1:80")
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("got %v, want the refusal as the reason", err)
	}
	t.Log(err)
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("reason spans lines: %q", err)
	}
}

// A server that accepts and never answers must not hold a read past the
// deadline, though Xray's connections ignore deadlines themselves.
func TestSilentServerDeadline(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close() // held open, silent
		}
	}()
	e := engine(t)
	tun, err := e.Open(context.Background(), parse(t, "vless://"+testID+"@"+l.Addr().String()+"?security=none"))
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = get(ctx, tun, "127.0.0.1:80")
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("read held for %s past a 500ms deadline", took)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v, want a timeout", err)
	}
}

// Closing a tunnel closes the pooled connection gRPC keeps behind it, and
// gRPC cannot reconnect it.
func TestCloseReleasesPooledSockets(t *testing.T) {
	target := check204(t)
	e := engine(t)
	port := freePort(t, "tcp")
	server(t, fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
		"settings": {"clients": [{"id": %q}], "decryption": "none"},
		"streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "svc"}}}`, port, testID))

	before := sockets.sockets()
	tun, err := e.Open(context.Background(), parse(t, fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=grpc&serviceName=svc", testID, port)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if code, err := get(ctx, tun, target); err != nil || code != 204 {
		t.Fatalf("got %d, %v", code, err)
	}
	if sockets.sockets() <= before {
		t.Fatal("the gRPC connection was not tracked")
	}
	tun.Close()
	if n := sockets.sockets(); n != before {
		t.Fatalf("%d sockets still tracked after close, want %d", n, before)
	}
	// A reconnect for the closed tunnel is refused, not dialed.
	time.Sleep(700 * time.Millisecond)
	if n := sockets.sockets(); n != before {
		t.Fatalf("%d sockets tracked after a reconnect window, want %d", n, before)
	}
}

// The check request and the exit-IP request both used to ask the endpoint to
// close the connection after its answer. A link's server passes that close on
// as a WebSocket close frame right behind the answer, Xray takes the frame for
// a failed outbound, and its pipe throws away what the reader has not taken
// yet. A working WebSocket link came out dead with "websocket: close 1000
// (normal)": one check in twenty run alone, four in ten among 32 at once.
func TestWebSocketLinkOutlivesTheAnswer(t *testing.T) {
	target := check204(t)
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	check := probe.Check{Host: host, Port: uint16(port), Path: "/generate_204", Status: 204}

	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "203.0.113.7")
	}))
	t.Cleanup(echo.Close)
	saved := geo.EchoURL
	geo.EchoURL = echo.URL
	t.Cleanup(func() { geo.EchoURL = saved })

	e := engine(t)
	wsPort := freePort(t, "tcp")
	server(t, fmt.Sprintf(`{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
		"settings": {"clients": [{"id": %q}], "decryption": "none"},
		"streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}`, wsPort, testID))
	l := parse(t, fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=ws&path=/ws", testID, wsPort))

	// Few enough to leave the loopback interface alone: a thousand connections
	// a second make macOS drop SYNs, and a check then times out on its own.
	const checks, atOnce = 60, 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed = make(map[string]int)
	)
	slots := make(chan struct{}, atOnce)
	for range checks {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			fail := func(what string, err error) {
				mu.Lock()
				failed[what+": "+err.Error()]++
				mu.Unlock()
			}
			tun, err := e.Open(context.Background(), l)
			if err != nil {
				fail("open", err)
				return
			}
			defer tun.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := probe.ProbeLink(ctx, tun, check); err != nil {
				fail("check", err)
				return
			}
			if _, err := geo.ExitIP(ctx, tun); err != nil {
				fail("exit IP", err)
			}
		}()
	}
	wg.Wait()
	for what, n := range failed {
		t.Errorf("%d of %d checks of a working link failed: %s", n, checks, what)
	}
}

// A vmess "type" of "none", the header type's default, used to become the
// XHTTP mode, and Xray refused the outbound: "unsupported mode: none".
func TestVMessXHTTPTypeNoneBuilds(t *testing.T) {
	body := `{"add":"1.2.3.4","port":"443","id":"` + testID + `","net":"xhttp","type":"none","host":"a.example.com","path":"/x","tls":"tls","sni":"a.example.com"}`
	l := parse(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(body)))
	if _, err := build(l, "x"); err != nil {
		t.Fatalf("build: %v", err)
	}
}

func TestInsecureNeverInJSON(t *testing.T) {
	l := parse(t, "trojan://pw@example.com:443?allowInsecure=1&sni=example.com")
	if !l.Insecure {
		t.Fatal("insecure flag not read")
	}
	raw, err := l.Outbound("x")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "allowInsecure") {
		t.Fatalf("Xray refuses allowInsecure in JSON, but the outbound carries it: %s", raw)
	}
	if _, err := build(l, "x"); err != nil {
		t.Fatalf("build: %v", err)
	}
}
