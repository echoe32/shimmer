package pipeline

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"shimmer/internal/dial"
	"shimmer/internal/geo"
	"shimmer/internal/probe"
)

const (
	echoURL  = "http://echo.test/ip" // never resolved: the request goes to the proxy
	exitAddr = "203.0.113.9"
)

// forwardProxy is a cleartext-only HTTP proxy: it refuses CONNECT and answers
// absolute-URI requests for the echo endpoint after delay.
func forwardProxy(t *testing.T, delay time.Duration) (probe.Proxy, *atomic.Int64) {
	t.Helper()
	var connects atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connects.Add(1)
			http.Error(w, "no tunnels here", http.StatusMethodNotAllowed)
			return
		}
		if r.RequestURI != echoURL {
			http.Error(w, "not the echo endpoint", http.StatusBadRequest)
			return
		}
		time.Sleep(delay)
		io.WriteString(w, exitAddr+"\n")
	}))
	t.Cleanup(srv.Close)

	restore := geo.PlainEchoURL
	geo.PlainEchoURL = echoURL
	t.Cleanup(func() { geo.PlainEchoURL = restore })

	addr := srv.Listener.Addr().(*net.TCPAddr)
	return probe.Proxy{Host: addr.IP.String(), Port: uint16(addr.Port)}, &connects
}

// lateProber finds the proxy with only margin left on its deadline, the way a
// slow proxy at the bottom of the ladder is found.
type lateProber struct {
	proto  probe.Protocol
	margin time.Duration
}

func (l lateProber) Name() probe.Protocol { return l.proto }

func (l lateProber) Probe(ctx context.Context, _ dial.Dialer, p probe.Proxy) (*probe.Result, error) {
	if dl, ok := ctx.Deadline(); ok {
		select {
		case <-time.After(time.Until(dl) - l.margin):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &probe.Result{Proxy: p, Protocol: l.proto, Alive: true, CheckedAt: time.Now()}, nil
}

// countryGeo places every address it is asked about.
type countryGeo struct{}

func (countryGeo) Lookup(context.Context, netip.Addr) (*geo.Info, error) {
	return &geo.Info{Country: "ZZ", ASN: 64496}, nil
}

func checkOne(t *testing.T, p *Pipeline, px probe.Proxy) probe.Result {
	t.Helper()
	in := make(chan probe.Proxy, 1)
	in <- px
	close(in)
	var got []probe.Result
	for res := range p.Run(context.Background(), in) {
		got = append(got, res)
	}
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	return got[0]
}

// A proxy classed HTTP refused CONNECT, so the exit check has to reach the
// echo endpoint with an absolute-URI request. It used to try CONNECT again,
// fail, and record the proxy's own address as the exit.
func TestExitCheckForwardsThroughHTTPProxy(t *testing.T) {
	px, connects := forwardProxy(t, 0)
	p := New(&net.Dialer{}, Options{
		Workers:      1,
		ProxyTimeout: 5 * time.Second,
		Probers:      []probe.Prober{&stubProber{proto: probe.HTTP}},
		CheckExitIP:  true,
	})

	res := checkOne(t, p, px)
	if !res.Alive {
		t.Fatalf("proxy not alive: %v", res.Err)
	}
	if got := res.ExitIP.String(); got != exitAddr {
		t.Errorf("exit IP %s, want %s from the echo endpoint", got, exitAddr)
	}
	if n := connects.Load(); n != 0 {
		t.Errorf("%d CONNECT requests sent to a proxy known to refuse them", n)
	}
}

// Detection used to be free to spend the whole deadline, and a proxy found at
// the bottom of the ladder reached the exit check with nothing left.
func TestExitCheckHasTimeAfterSlowDetection(t *testing.T) {
	const timeout = 2 * time.Second
	// The echo answer takes longer than detection leaves over, and less than
	// the share kept back for it.
	px, _ := forwardProxy(t, timeout/10)
	p := New(&net.Dialer{}, Options{
		Workers:      1,
		ProxyTimeout: timeout,
		Probers:      []probe.Prober{lateProber{proto: probe.HTTP, margin: timeout / 20}},
		CheckExitIP:  true,
	})

	res := checkOne(t, p, px)
	if !res.Alive {
		t.Fatalf("proxy not alive: %v", res.Err)
	}
	if got := res.ExitIP.String(); got != exitAddr {
		t.Errorf("exit IP %s, want %s: detection left the check no time", got, exitAddr)
	}
}

// When the echo endpoint cannot be reached, the proxy's own address used to be
// recorded as its exit, indistinguishable from a real answer.
func TestFailedExitCheckRecordsNoExitIP(t *testing.T) {
	p := New(&pipeDialer{}, Options{ // a pipe nobody answers: the check times out
		Workers:      1,
		ProxyTimeout: 200 * time.Millisecond,
		Probers:      []probe.Prober{&stubProber{proto: probe.SOCKS5}},
		Geo:          countryGeo{},
		CheckExitIP:  true,
	})

	res := checkOne(t, p, probe.Proxy{Host: "192.0.2.1", Port: 1080})
	if !res.Alive {
		t.Fatalf("a failed exit check cost the proxy its result: %v", res.Err)
	}
	if res.ExitIP.IsValid() {
		t.Errorf("exit IP %s recorded, but the check never answered", res.ExitIP)
	}
	if res.Country != "" || res.ASN != 0 {
		t.Errorf("country %q, ASN %d placed without an exit address", res.Country, res.ASN)
	}
}

// Without the check, the proxy's own address still stands in for the exit.
func TestWithoutExitCheckProxyAddressStandsIn(t *testing.T) {
	p := New(&pipeDialer{}, Options{
		Workers:      1,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{&stubProber{proto: probe.SOCKS5}},
		Geo:          countryGeo{},
	})

	res := checkOne(t, p, probe.Proxy{Host: "192.0.2.1", Port: 1080})
	if got := res.ExitIP.String(); got != "192.0.2.1" {
		t.Errorf("exit IP %s, want the proxy's own 192.0.2.1", got)
	}
	if res.Country != "ZZ" {
		t.Errorf("country %q, want ZZ", res.Country)
	}
}
