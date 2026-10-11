package pipeline

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"shimmer/internal/dial"
	"shimmer/internal/geo"
	"shimmer/internal/probe"
)

// pipeDialer hands out a connected pipe: enough for the TCP-reachability step,
// with no network involved.
type pipeDialer struct {
	dials atomic.Int64
	err   error
}

func (p *pipeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	p.dials.Add(1)
	if p.err != nil {
		return nil, p.err
	}
	client, server := net.Pipe()
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	return client, nil
}

// stubProber answers immediately and records how many probes overlap.
type stubProber struct {
	proto   probe.Protocol
	delay   time.Duration
	err     error
	inFlong atomic.Int64
	peak    atomic.Int64
}

func (s *stubProber) Name() probe.Protocol { return s.proto }

func (s *stubProber) Probe(ctx context.Context, d dial.Dialer, p probe.Proxy) (*probe.Result, error) {
	n := s.inFlong.Add(1)
	for {
		peak := s.peak.Load()
		if n <= peak || s.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	defer s.inFlong.Add(-1)

	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return &probe.Result{
		Proxy:      p,
		Protocol:   s.proto,
		Alive:      true,
		ConnectRTT: time.Millisecond,
		TotalRTT:   2 * time.Millisecond,
		CheckedAt:  time.Now(),
	}, nil
}

func feed(n int) <-chan probe.Proxy {
	ch := make(chan probe.Proxy, n)
	for i := range n {
		ch <- probe.Proxy{Host: "192.0.2.1", Port: uint16(1024 + i)}
	}
	close(ch)
	return ch
}

func TestRunChecksEveryProxyWithinWorkerBound(t *testing.T) {
	const (
		count   = 500
		workers = 16
	)
	st := &stubProber{proto: probe.SOCKS5, delay: time.Millisecond}
	p := New(&pipeDialer{}, Options{
		Workers:      workers,
		ProxyTimeout: 5 * time.Second,
		Probers:      []probe.Prober{st},
	})

	var got, alive int
	for res := range p.Run(context.Background(), feed(count)) {
		got++
		if res.Alive {
			alive++
		}
		if res.Protocol != probe.SOCKS5 {
			t.Fatalf("protocol %s, want socks5", res.Protocol)
		}
	}
	if got != count {
		t.Errorf("got %d results, want %d", got, count)
	}
	if alive != count {
		t.Errorf("%d alive, want %d", alive, count)
	}
	if peak := st.peak.Load(); peak > workers {
		t.Errorf("%d probes in flight at once, want at most %d", peak, workers)
	}
	if p.Checked() != int64(count) {
		t.Errorf("Checked = %d, want %d", p.Checked(), count)
	}
}

func TestRunClosesOutputOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := New(&pipeDialer{}, Options{
		Workers:      4,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{&stubProber{proto: probe.HTTP, delay: 20 * time.Millisecond}},
	})

	out := p.Run(ctx, feed(10_000))
	<-out
	cancel()

	done := make(chan struct{})
	go func() {
		for range out { //nolint:revive // draining
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not close its channel after cancellation")
	}
}

func TestUnreachableProxyIsRecordedNotDropped(t *testing.T) {
	d := &pipeDialer{err: errors.New("connection refused")}
	p := New(d, Options{
		Workers:      4,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{&stubProber{proto: probe.SOCKS5}},
	})

	var got int
	for res := range p.Run(context.Background(), feed(8)) {
		got++
		if res.Alive {
			t.Error("unreachable proxy reported as alive")
		}
		if res.Err == nil {
			t.Error("unreachable proxy has no error recorded")
		}
		if res.Protocol != probe.Unknown {
			t.Errorf("protocol %s, want unknown", res.Protocol)
		}
	}
	if got != 8 {
		t.Errorf("got %d results, want 8", got)
	}
	// One dial per proxy: the reachability check fails and the ladder is skipped.
	if d.dials.Load() != 8 {
		t.Errorf("%d dials, want 8", d.dials.Load())
	}
}

func TestProxyTimeoutCapsOneProxy(t *testing.T) {
	p := New(&pipeDialer{}, Options{
		Workers:      2,
		ProxyTimeout: 100 * time.Millisecond,
		Probers:      []probe.Prober{&stubProber{proto: probe.SOCKS5, delay: time.Hour}},
	})

	start := time.Now()
	var got int
	for res := range p.Run(context.Background(), feed(4)) {
		got++
		if res.Alive {
			t.Error("a probe that never answers reported as alive")
		}
	}
	if got != 4 {
		t.Errorf("got %d results, want 4", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("run took %s; the per-proxy deadline did not hold", elapsed)
	}
}

// A proxy that only a skipped protocol works on is marked left out, not dead:
// recorded dead, it would move a live row in the database into dead.
func TestSkippedProtocolLeavesProxyOut(t *testing.T) {
	p := New(&pipeDialer{}, Options{
		Workers:      4,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{&stubProber{proto: probe.HTTP, err: probe.ErrNotSupported}},
		Skipped:      []probe.Prober{&stubProber{proto: probe.SOCKS4}},
	})
	var got int
	for res := range p.Run(context.Background(), feed(8)) {
		got++
		if !res.LeftOut || res.Alive {
			t.Errorf("%s: left out %v, alive %v; want left out and not alive", res.Proxy, res.LeftOut, res.Alive)
		}
	}
	if got != 8 {
		t.Errorf("got %d results, want 8", got)
	}
	if p.Checked() != 8 || p.LeftOut() != 8 || p.Alive() != 0 {
		t.Errorf("checked %d, left out %d, alive %d; want 8, 8, 0", p.Checked(), p.LeftOut(), p.Alive())
	}
}

// A proxy no protocol works on is still recorded dead, with the skipped
// protocols' failures in its error too.
func TestSkippedProtocolsFailingIsDead(t *testing.T) {
	p := New(&pipeDialer{}, Options{
		Workers:      4,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{&stubProber{proto: probe.HTTP, err: errors.New("wanted failed")}},
		Skipped:      []probe.Prober{&stubProber{proto: probe.SOCKS4, err: errors.New("skipped failed")}},
	})
	var got int
	for res := range p.Run(context.Background(), feed(4)) {
		got++
		if res.Alive || res.LeftOut {
			t.Errorf("proxy no protocol works on: alive %v, left out %v; want dead", res.Alive, res.LeftOut)
		}
		if res.Err == nil || !strings.Contains(res.Err.Error(), "wanted failed") || !strings.Contains(res.Err.Error(), "skipped failed") {
			t.Errorf("error %v, want both ladders' failures", res.Err)
		}
	}
	if got != 4 || p.LeftOut() != 0 {
		t.Errorf("got %d results, left out %d; want 4 and 0", got, p.LeftOut())
	}
}

// checked_at is when the check finished. A dead proxy used to be stamped as
// its check began, early by as long as the check took, and a live one before
// its exit address and geography were looked up.
func TestCheckedAtIsWhenCheckFinished(t *testing.T) {
	const took = 50 * time.Millisecond
	for _, c := range []struct {
		name string
		opts Options
	}{
		{"dead", Options{Probers: []probe.Prober{&stubProber{proto: probe.SOCKS5, delay: took, err: errors.New("no answer")}}}},
		{"alive", Options{Probers: []probe.Prober{&stubProber{proto: probe.SOCKS5}}, Geo: slowGeo{took}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.opts.Workers, c.opts.ProxyTimeout = 1, time.Second
			start := time.Now()
			res := checkOne(t, New(&pipeDialer{}, c.opts), probe.Proxy{Host: "192.0.2.1", Port: 1080})
			if early := start.Add(took).Sub(res.CheckedAt); early > 0 {
				t.Errorf("checked_at is %s before the check could have finished", early)
			}
		})
	}
}

// slowGeo takes a while to place an address.
type slowGeo struct{ delay time.Duration }

func (g slowGeo) Lookup(context.Context, netip.Addr) (*geo.Info, error) {
	time.Sleep(g.delay)
	return &geo.Info{Country: "ZZ"}, nil
}

// The skipped protocols are tried only when no wanted one works.
func TestSkippedProtocolsNotTriedOnLiveProxy(t *testing.T) {
	skipped := &stubProber{proto: probe.SOCKS4}
	p := New(&pipeDialer{}, Options{
		Workers:      4,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{&stubProber{proto: probe.SOCKS5}},
		Skipped:      []probe.Prober{skipped},
	})
	for res := range p.Run(context.Background(), feed(4)) {
		if !res.Alive || res.Protocol != probe.SOCKS5 {
			t.Errorf("%s: protocol %s, alive %v; want a live socks5", res.Proxy, res.Protocol, res.Alive)
		}
	}
	if skipped.peak.Load() != 0 {
		t.Error("skipped protocol tried on a proxy a wanted one found")
	}
}
