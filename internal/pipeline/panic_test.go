package pipeline

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"shimmer/internal/dial"
	"shimmer/internal/probe"
)

// panicProber crashes on every other proxy, so one run covers both paths.
type panicProber struct {
	n atomic.Int64
}

func (*panicProber) Name() probe.Protocol { return probe.SOCKS5 }

func (p *panicProber) Probe(ctx context.Context, d dial.Dialer, px probe.Proxy) (*probe.Result, error) {
	if p.n.Add(1)%2 == 0 {
		var b []byte
		_ = b[3] // the shape of a real bug: a short reply from a hostile proxy
	}
	return &probe.Result{
		Proxy:     px,
		Protocol:  probe.SOCKS5,
		Alive:     true,
		CheckedAt: time.Now(),
	}, nil
}

func TestPanicIsRecordedAsDeadProxy(t *testing.T) {
	const count = 20

	var reported atomic.Int64
	var gotStack atomic.Bool
	p := New(&pipeDialer{}, Options{
		Workers:      4,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{&panicProber{}},
		OnPanic: func(px probe.Proxy, v any, stack []byte) {
			reported.Add(1)
			if bytes.Contains(stack, []byte("pipeline")) {
				gotStack.Store(true)
			}
		},
	})

	var got, panicked int
	for res := range p.Run(context.Background(), feed(count)) {
		got++
		if res.Err != nil {
			panicked++
			if !strings.Contains(res.Err.Error(), "probe panicked") {
				t.Errorf("error %q, want a panic report", res.Err)
			}
			if res.Alive {
				t.Error("a probe that panicked was recorded alive")
			}
			if res.Proxy.Port == 0 {
				t.Error("panic result lost the proxy it was checking")
			}
		}
	}

	if got != count {
		t.Errorf("got %d results, want %d: a panic ended the run", got, count)
	}
	if panicked != count/2 {
		t.Errorf("%d results carry a panic, want %d", panicked, count/2)
	}
	if p.Panics() != int64(count/2) {
		t.Errorf("Panics = %d, want %d", p.Panics(), count/2)
	}
	if reported.Load() != int64(count/2) {
		t.Errorf("OnPanic called %d times, want %d", reported.Load(), count/2)
	}
	if !gotStack.Load() {
		t.Error("OnPanic got no usable stack")
	}
}

func TestPanicWithoutHandlerStillContinues(t *testing.T) {
	p := New(&pipeDialer{}, Options{
		Workers:      2,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{&panicProber{}},
	})

	var got int
	for range p.Run(context.Background(), feed(6)) {
		got++
	}
	if got != 6 {
		t.Fatalf("got %d results, want 6", got)
	}
	if p.Panics() == 0 {
		t.Error("Panics = 0, want the crashed probes counted")
	}
}
