// Package pipeline fans proxies out to a bounded worker pool and funnels
// results to a single writer.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"shimmer/internal/dial"
	"shimmer/internal/geo"
	"shimmer/internal/link"
	"shimmer/internal/probe"
)

// Options tunes the run.
type Options struct {
	Workers      int           // concurrent probes; each holds a socket, so cap this
	ProxyTimeout time.Duration // per-proxy deadline across all probe attempts

	Probers     []probe.Prober // protocol ladder; probe.Ladder() when both it and Skipped are empty
	Skipped     []probe.Prober // tried only when Probers find nothing; a proxy one of these finds is marked LeftOut
	Geo         geo.Lookup     // optional country/ASN for the exit address
	CheckExitIP bool           // ask an echo endpoint for the true exit address; none is recorded when it cannot tell

	// Links opens a tunnel through a share link. Without it, every link is
	// recorded dead.
	Links Tunnels
	// Check is the endpoint a link must reach; zero means probe.DefaultCheck.
	// Classic proxies are checked against the endpoint their probers carry.
	Check probe.Check
	// Skip is the protocols left out of the results. For classic proxies the
	// split is already in Probers and Skipped. A link names its protocol, so
	// a link of a skipped one is marked LeftOut without being checked.
	Skip []probe.Protocol

	// OnPanic is called when probing one proxy panics. The proxy is recorded
	// as dead either way; this only decides whether anyone hears about the
	// bug. Nil keeps the panic silent.
	OnPanic func(px probe.Proxy, value any, stack []byte)
}

// Tunnels opens a route through one share link, for as long as its check runs.
type Tunnels interface {
	Open(ctx context.Context, l *link.Link) (dial.Tunnel, error)
}

// errNothingWanted is the failure of a classic proxy when -skip names every
// classic protocol: the only question left is whether to leave it out.
var errNothingWanted = errors.New("every classic protocol is skipped")

// Defaults applied when Options leaves a field at zero.
const (
	defaultWorkers = 256
	defaultTimeout = 10 * time.Second
)

// exitShare is the fraction of ProxyTimeout (one part in exitShare) that
// detection leaves for the exit-IP check. Without it a proxy found at the
// bottom of the ladder reached the check with no time left, every time.
const exitShare = 4

// Pipeline owns the worker pool. The dialer is shared, never per-worker.
type Pipeline struct {
	dialer dial.Dialer
	opts   Options

	checked atomic.Int64
	alive   atomic.Int64
	leftOut atomic.Int64
	panics  atomic.Int64
}

// New builds a pipeline over a dialer.
func New(d dial.Dialer, opts Options) *Pipeline {
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	if opts.ProxyTimeout <= 0 {
		opts.ProxyTimeout = defaultTimeout
	}
	if len(opts.Probers) == 0 && len(opts.Skipped) == 0 {
		opts.Probers = probe.Ladder()
	}
	if opts.Check == (probe.Check{}) {
		opts.Check = probe.DefaultCheck
	}
	return &Pipeline{dialer: d, opts: opts}
}

// Run consumes proxies until the channel closes or ctx is cancelled, and
// closes the returned channel when every worker has finished.
func (p *Pipeline) Run(ctx context.Context, in <-chan probe.Proxy) <-chan probe.Result {
	out := make(chan probe.Result, p.opts.Workers)

	var wg sync.WaitGroup
	wg.Add(p.opts.Workers)
	for range p.opts.Workers {
		go func() {
			defer wg.Done()
			p.work(ctx, in, out)
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// Checked and Alive report progress while a run is in flight. LeftOut counts
// the results marked LeftOut, because only a skipped protocol worked. Panics
// counts the probes that crashed and were recorded as dead.
func (p *Pipeline) Checked() int64 { return p.checked.Load() }
func (p *Pipeline) Alive() int64   { return p.alive.Load() }
func (p *Pipeline) LeftOut() int64 { return p.leftOut.Load() }
func (p *Pipeline) Panics() int64  { return p.panics.Load() }

// work pulls one proxy at a time. Nothing is buffered per worker, so a slow
// consumer slows the whole pool instead of growing memory behind it.
func (p *Pipeline) work(ctx context.Context, in <-chan probe.Proxy, out chan<- probe.Result) {
	for {
		select {
		case <-ctx.Done():
			return
		case px, ok := <-in:
			if !ok {
				return
			}
			res := p.check(ctx, px)
			p.checked.Add(1)
			switch {
			case res.LeftOut:
				p.leftOut.Add(1)
			case res.Alive:
				p.alive.Add(1)
			}
			select {
			case out <- res:
			case <-ctx.Done():
				return
			}
		}
	}
}

// check runs one proxy through the ladder under a single deadline that covers
// every attempt, so one proxy can never hold a worker longer than ProxyTimeout.
//
// A panic below this point is turned into a dead result. Probers parse bytes
// from hosts that owe them nothing, so a malformed answer that trips a bounds
// check must cost one proxy, not the whole run and every result still buffered
// behind it.
func (p *Pipeline) check(parent context.Context, px probe.Proxy) (res probe.Result) {
	ctx, cancel := context.WithTimeout(parent, p.opts.ProxyTimeout)
	defer cancel()

	defer func() {
		v := recover()
		if v == nil {
			return
		}
		stack := debug.Stack()
		if p.opts.OnPanic != nil {
			p.opts.OnPanic(px, v, stack)
		}
		p.panics.Add(1)
		res = probe.Result{
			Proxy:     px,
			Protocol:  probe.Unknown,
			CheckedAt: time.Now(),
			Err:       fmt.Errorf("probe panicked: %v", v),
		}
	}()

	// Stamped at every return below, once the check has finished: stamped here,
	// a dead proxy that used the whole timeout was dated that much early.
	res = probe.Result{Proxy: px, Protocol: probe.Unknown}

	// Detection gets a deadline of its own, short of the proxy's, when an
	// exit-IP check has to follow it.
	detectCtx := ctx
	if p.opts.CheckExitIP {
		var cancelDetect context.CancelFunc
		detectCtx, cancelDetect = context.WithTimeout(ctx, p.opts.ProxyTimeout-p.opts.ProxyTimeout/exitShare)
		defer cancelDetect()
	}

	if px.Link != nil {
		return p.checkLink(ctx, detectCtx, px)
	}

	// One cheap TCP connect first. Most candidates in a scraped list are simply
	// dead, and this rejects them for the cost of one handshake instead of one
	// per protocol. It also gives an honest ConnectRTT even for a proxy that
	// answers TCP but speaks no protocol we know.
	rtt, err := probe.ConnectRTT(detectCtx, p.dialer, px)
	res.ConnectRTT = rtt
	if err != nil {
		res.Err = err
		res.CheckedAt = time.Now()
		return res
	}

	// Detect takes an empty ladder for the full one; here it means every
	// classic protocol is skipped.
	var found *probe.Result
	err = errNothingWanted
	if len(p.opts.Probers) > 0 {
		found, err = probe.Detect(detectCtx, p.dialer, px, p.opts.Probers)
	}
	if err != nil {
		res.Err = err
		res.LeftOut = p.skippedWorks(detectCtx, px, &res)
		res.CheckedAt = time.Now()
		return res
	}
	res = *found
	res.ConnectRTT = rtt
	p.enrich(ctx, &res, nil)
	res.CheckedAt = time.Now() // the exit-IP check can take a quarter of the timeout
	return res
}

// checkLink proves a share link the way check proves a proxy: a request for
// the check endpoint must come back with its own answer. The link names its
// protocol, so there is nothing to detect, and the request goes through an
// outbound built from the link.
func (p *Pipeline) checkLink(ctx, detectCtx context.Context, px probe.Proxy) probe.Result {
	res := probe.Result{Proxy: px, Protocol: probe.Protocol(px.Link.Protocol)}
	if slices.Contains(p.opts.Skip, res.Protocol) {
		res.LeftOut = true
		res.CheckedAt = time.Now()
		return res
	}

	// The same cheap TCP connect a proxy gets first, and for the same reason.
	// A link over UDP (Hysteria2, mKCP) has no TCP listener to find.
	if !px.Link.UDP() {
		rtt, err := probe.ConnectRTT(detectCtx, p.dialer, px)
		res.ConnectRTT = rtt
		if err != nil {
			res.Err = err
			res.CheckedAt = time.Now()
			return res
		}
	}

	if p.opts.Links == nil {
		res.Err = errors.New("no engine to check share links with")
		res.CheckedAt = time.Now()
		return res
	}
	tun, err := p.opts.Links.Open(detectCtx, px.Link)
	if err != nil {
		res.Err = err
		res.CheckedAt = time.Now()
		return res
	}
	defer tun.Close() // after the exit-IP check, which runs through it too

	total, err := probe.ProbeLink(detectCtx, tun, p.opts.Check)
	if err != nil {
		res.Err = err
		res.CheckedAt = time.Now()
		return res
	}
	res.Alive = true
	res.TotalRTT = total
	p.enrich(ctx, &res, tun)
	res.CheckedAt = time.Now()
	return res
}

// skippedWorks runs the skipped protocols, with whatever time the wanted ones
// left, on a proxy none of the wanted ones found. A proxy that speaks one of
// them is no dead proxy, and recording it as one would move a proxy the
// database holds as live into dead. A proxy that speaks none of them has
// their failures added to its error.
func (p *Pipeline) skippedWorks(ctx context.Context, px probe.Proxy, res *probe.Result) bool {
	if len(p.opts.Skipped) == 0 || ctx.Err() != nil {
		return false
	}
	_, err := probe.Detect(ctx, p.dialer, px, p.opts.Skipped)
	if err == nil {
		return true
	}
	res.Err = errors.Join(res.Err, err)
	return false
}

// enrich fills in the exit address and its geography. A failure here leaves the
// proxy alive: the probe already proved it forwards traffic. tun is the route
// through a share link, nil for a classic proxy.
func (p *Pipeline) enrich(ctx context.Context, res *probe.Result, tun dial.Dialer) {
	res.ExitIP = p.exitIP(ctx, res, tun)
	if p.opts.Geo == nil || !res.ExitIP.IsValid() {
		return
	}
	info, err := p.opts.Geo.Lookup(ctx, res.ExitIP)
	if err != nil || info == nil {
		return
	}
	res.Country = info.Country
	res.ASN = info.ASN
}

// exitIP reports the address the proxy's traffic leaves from. With the check
// on, only an address the echo endpoint saw counts: the proxy's own address is
// a guess, and a guess recorded as the check's answer cannot be told apart
// from a real one. With the check off, the proxy's own address stands in,
// which is only right when the proxy does not relay onward.
func (p *Pipeline) exitIP(ctx context.Context, res *probe.Result, tun dial.Dialer) netip.Addr {
	if p.opts.CheckExitIP {
		addr, err := p.echo(ctx, res, tun)
		if err != nil {
			return netip.Addr{}
		}
		return addr
	}
	if addr, err := netip.ParseAddr(res.Proxy.Host); err == nil {
		return addr.Unmap()
	}
	return netip.Addr{}
}

// echo asks the echo endpoint through the proxy, the way the proxy was seen to
// carry traffic. One classed HTTP refused CONNECT, so it gets an absolute-URI
// request instead of a tunnel. A share link has its tunnel already.
func (p *Pipeline) echo(ctx context.Context, res *probe.Result, tun dial.Dialer) (netip.Addr, error) {
	if tun != nil {
		return geo.ExitIP(ctx, tun)
	}
	if res.Protocol == probe.HTTP {
		return geo.ExitIPForward(ctx, p.dialer, res.Proxy.Addr())
	}
	return geo.ExitIP(ctx, probe.Dialer(p.dialer, res.Proxy, res.Protocol))
}
