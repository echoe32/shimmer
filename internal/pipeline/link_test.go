package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	"shimmer/internal/dial"
	"shimmer/internal/geo"
	"shimmer/internal/link"
	"shimmer/internal/probe"
	"shimmer/internal/xray"
)

const linkID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// checkServer answers every request with status, as the check endpoint
// does with 204.
func checkServer(t *testing.T, status int) probe.Check {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().(*net.TCPAddr)
	return probe.Check{Host: addr.IP.String(), Port: uint16(addr.Port), Path: "/generate_204", Status: 204}
}

// fakeTunnels opens tunnels that connect straight to wherever they are
// asked, as a working link would, or fail as told.
type fakeTunnels struct {
	openErr error
	dialErr error

	opened, closed, dials atomic.Int64
}

func (f *fakeTunnels) Open(context.Context, *link.Link) (dial.Tunnel, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	f.opened.Add(1)
	return fakeTunnel{f}, nil
}

type fakeTunnel struct{ f *fakeTunnels }

func (t fakeTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	t.f.dials.Add(1)
	if t.f.dialErr != nil {
		return nil, t.f.dialErr
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func (t fakeTunnel) Close() error {
	t.f.closed.Add(1)
	return nil
}

func linkProxy(t *testing.T, s string) probe.Proxy {
	t.Helper()
	l, err := link.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return probe.Proxy{Host: l.Host, Port: l.Port, Link: l}
}

func TestLinkAlive(t *testing.T) {
	tunnels := &fakeTunnels{}
	p := New(&pipeDialer{}, Options{
		Workers:      1,
		ProxyTimeout: 2 * time.Second,
		Links:        tunnels,
		Check:        checkServer(t, 204),
	})
	res := checkOne(t, p, linkProxy(t, "vless://"+linkID+"@203.0.113.1:443?security=none#n"))
	if !res.Alive || res.Err != nil {
		t.Fatalf("alive %v, err %v; want alive", res.Alive, res.Err)
	}
	if res.Protocol != probe.VLESS || res.TotalRTT <= 0 {
		t.Errorf("protocol %q, total %s", res.Protocol, res.TotalRTT)
	}
	if tunnels.opened.Load() != 1 || tunnels.closed.Load() != 1 {
		t.Errorf("opened %d, closed %d tunnels; want 1 and 1", tunnels.opened.Load(), tunnels.closed.Load())
	}
}

// A link is alive only if the check endpoint itself answered through it.
func TestLinkWithWrongAnswerIsDead(t *testing.T) {
	p := New(&pipeDialer{}, Options{
		Workers:      1,
		ProxyTimeout: 2 * time.Second,
		Links:        &fakeTunnels{},
		Check:        checkServer(t, 200),
	})
	res := checkOne(t, p, linkProxy(t, "trojan://pw@203.0.113.1:443"))
	if res.Alive || res.Err == nil || !strings.Contains(res.Err.Error(), "answered 200") {
		t.Fatalf("alive %v, err %v; want dead for the wrong answer", res.Alive, res.Err)
	}
	if res.Protocol != probe.Trojan {
		t.Errorf("protocol %q, want trojan: a dead link still names its protocol", res.Protocol)
	}
}

func TestLinkThatFailsIsDeadWithItsReason(t *testing.T) {
	for _, tunnels := range []*fakeTunnels{
		{openErr: errors.New("outbound: bad config")},
		{dialErr: errors.New("reality: handshake failed")},
	} {
		p := New(&pipeDialer{}, Options{Workers: 1, ProxyTimeout: time.Second, Links: tunnels, Check: checkServer(t, 204)})
		res := checkOne(t, p, linkProxy(t, "vless://"+linkID+"@203.0.113.1:443"))
		want := tunnels.openErr
		if want == nil {
			want = tunnels.dialErr
		}
		if res.Alive || !errors.Is(res.Err, want) {
			t.Errorf("alive %v, err %v; want dead with %v", res.Alive, res.Err, want)
		}
		if tunnels.opened.Load() != tunnels.closed.Load() {
			t.Errorf("opened %d tunnels, closed %d", tunnels.opened.Load(), tunnels.closed.Load())
		}
	}
}

// The TCP connect rejects a dead server before an outbound is built for it.
func TestUnreachableLinkIsNotOpened(t *testing.T) {
	tunnels := &fakeTunnels{}
	p := New(&pipeDialer{err: errors.New("connection refused")}, Options{Workers: 1, ProxyTimeout: time.Second, Links: tunnels})
	res := checkOne(t, p, linkProxy(t, "vless://"+linkID+"@203.0.113.1:443"))
	if res.Alive || res.Err == nil || !strings.Contains(res.Err.Error(), "refused") {
		t.Errorf("alive %v, err %v; want dead, refused", res.Alive, res.Err)
	}
	if tunnels.opened.Load() != 0 {
		t.Error("an outbound was built for a server that refused TCP")
	}
}

// Hysteria2 runs over UDP: a TCP connect to its port proves nothing, and
// refused would be the usual answer.
func TestUDPLinkSkipsTCPConnect(t *testing.T) {
	d := &pipeDialer{err: errors.New("connection refused")}
	p := New(d, Options{Workers: 1, ProxyTimeout: 2 * time.Second, Links: &fakeTunnels{}, Check: checkServer(t, 204)})
	res := checkOne(t, p, linkProxy(t, "hy2://auth@203.0.113.1:443/?sni=example.com"))
	if !res.Alive {
		t.Fatalf("hysteria2 link dead: %v", res.Err)
	}
	if d.dials.Load() != 0 || res.ConnectRTT != 0 {
		t.Errorf("%d TCP dials, connect %s; want none", d.dials.Load(), res.ConnectRTT)
	}
}

// A link names its protocol, so one of a skipped protocol is left out
// without a connection made.
func TestSkippedLinkProtocolIsLeftOutUnchecked(t *testing.T) {
	d := &pipeDialer{}
	tunnels := &fakeTunnels{}
	p := New(d, Options{Workers: 1, ProxyTimeout: time.Second, Links: tunnels, Skip: []probe.Protocol{probe.Shadowsocks}})
	res := checkOne(t, p, linkProxy(t, "ss://YWVzLTEyOC1nY206cGFzcw@203.0.113.1:8388"))
	if !res.LeftOut || res.Alive {
		t.Errorf("left out %v, alive %v; want left out", res.LeftOut, res.Alive)
	}
	if d.dials.Load() != 0 || tunnels.opened.Load() != 0 {
		t.Error("a link of a skipped protocol was checked")
	}
	if p.LeftOut() != 1 {
		t.Errorf("LeftOut() = %d, want 1", p.LeftOut())
	}
}

func TestLinkWithoutEngineIsDead(t *testing.T) {
	p := New(&pipeDialer{}, Options{Workers: 1, ProxyTimeout: time.Second})
	res := checkOne(t, p, linkProxy(t, "vless://"+linkID+"@203.0.113.1:443"))
	if res.Alive || res.Err == nil {
		t.Errorf("alive %v, err %v; want dead", res.Alive, res.Err)
	}
}

// The exit address of a link is asked for through the link.
func TestLinkExitIPThroughTunnel(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, exitAddr+"\n")
	}))
	t.Cleanup(echo.Close)
	restore := geo.EchoURL
	geo.EchoURL = echo.URL
	t.Cleanup(func() { geo.EchoURL = restore })

	tunnels := &fakeTunnels{}
	p := New(&pipeDialer{}, Options{
		Workers:      1,
		ProxyTimeout: 2 * time.Second,
		Links:        tunnels,
		Check:        checkServer(t, 204),
		CheckExitIP:  true,
		Geo:          countryGeo{},
	})
	res := checkOne(t, p, linkProxy(t, "vless://"+linkID+"@203.0.113.1:443"))
	if !res.Alive {
		t.Fatalf("dead: %v", res.Err)
	}
	if res.ExitIP.String() != exitAddr || res.Country != "ZZ" {
		t.Errorf("exit %s, country %q; want %s, ZZ", res.ExitIP, res.Country, exitAddr)
	}
	if n := tunnels.dials.Load(); n != 2 {
		t.Errorf("%d dials through the tunnel, want 2: the check and the echo", n)
	}
}

// With every classic protocol skipped, a classic proxy is only tried to be
// left out: the empty ladder must not turn into the full one.
func TestEveryClassicProtocolSkipped(t *testing.T) {
	p := New(&pipeDialer{}, Options{
		Workers:      1,
		ProxyTimeout: time.Second,
		Skipped:      []probe.Prober{&stubProber{proto: probe.SOCKS5}},
	})
	res := checkOne(t, p, probe.Proxy{Host: "203.0.113.1", Port: 1080})
	if !res.LeftOut || res.Alive {
		t.Errorf("left out %v, alive %v; want left out", res.LeftOut, res.Alive)
	}

	p = New(&pipeDialer{}, Options{
		Workers:      1,
		ProxyTimeout: time.Second,
		Skipped:      []probe.Prober{&stubProber{proto: probe.SOCKS5, err: errors.New("no socks")}},
	})
	res = checkOne(t, p, probe.Proxy{Host: "203.0.113.1", Port: 1080})
	if res.LeftOut || res.Alive || !errors.Is(res.Err, errNothingWanted) {
		t.Errorf("left out %v, alive %v, err %v; want dead", res.LeftOut, res.Alive, res.Err)
	}
}

// Through a real Xray server: the tunnel, the deadline and the check
// request fit together.
func TestLinkThroughXray(t *testing.T) {
	check := checkServer(t, 204)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg, err := serial.LoadJSONConfig(strings.NewReader(fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
			"settings": {"clients": [{"id": %q}], "decryption": "none"},
			"streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}],
		"outbounds": [{"protocol": "freedom"}]
	}`, port, linkID)))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	engine, err := xray.New()
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	p := New(&net.Dialer{}, Options{Workers: 2, ProxyTimeout: 3 * time.Second, Links: engine, Check: check})
	in := make(chan probe.Proxy, 2)
	in <- linkProxy(t, fmt.Sprintf("vless://%s@127.0.0.1:%d?type=ws&path=/ws&security=none#good", linkID, port))
	in <- linkProxy(t, fmt.Sprintf("vless://%s@127.0.0.1:%d?type=ws&path=/other&security=none#wrong-path", linkID, port))
	close(in)
	got := map[string]probe.Result{}
	for res := range p.Run(context.Background(), in) {
		got[res.Proxy.Link.Name] = res
	}
	if r := got["good"]; !r.Alive || r.ConnectRTT <= 0 || r.TotalRTT <= 0 {
		t.Errorf("good link: alive %v, connect %s, total %s, err %v", r.Alive, r.ConnectRTT, r.TotalRTT, r.Err)
	}
	if r := got["wrong-path"]; r.Alive || r.Err == nil {
		t.Errorf("link with the wrong path: alive %v, err %v; want dead", r.Alive, r.Err)
	}
}
