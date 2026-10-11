// Package probe determines whether a proxy is alive, which protocol it speaks,
// and how fast it is. Every probe dials through a dial.Dialer.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"shimmer/internal/dial"
	"shimmer/internal/link"
)

// Protocol is the wire protocol a proxy was confirmed to speak.
type Protocol string

const (
	Unknown Protocol = "unknown"
	SOCKS5  Protocol = "socks5"
	SOCKS4  Protocol = "socks4"
	HTTP    Protocol = "http"  // absolute-URI requests
	HTTPS   Protocol = "https" // CONNECT tunnelling

	// The protocols of share links. A link names its protocol, so these are
	// read, not detected.
	VLESS       Protocol = link.VLESS
	VMess       Protocol = link.VMess
	Trojan      Protocol = link.Trojan
	Shadowsocks Protocol = link.Shadowsocks
	Hysteria2   Protocol = link.Hysteria2
)

// Proxy is one candidate to check: a classic proxy, whose protocol is
// detected, or a share link, which carries its protocol and credentials.
type Proxy struct {
	Host string
	Port uint16
	Link *link.Link // nil for a classic proxy
}

// Addr renders the proxy as a dialable "host:port".
func (p Proxy) Addr() string { return net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))) }

// String implements fmt.Stringer.
func (p Proxy) String() string {
	if p.Link != nil {
		return p.Link.Protocol + " " + p.Addr()
	}
	return p.Addr()
}

// Result is what the pipeline records for a single proxy.
type Result struct {
	Proxy      Proxy
	Protocol   Protocol
	Alive      bool
	ConnectRTT time.Duration // TCP handshake to the proxy
	TotalRTT   time.Duration // end-to-end request through the proxy
	ExitIP     netip.Addr
	Country    string
	ASN        uint
	Err        error
	CheckedAt  time.Time

	// LeftOut marks a proxy that only a skipped protocol worked on. It gets
	// no record, and the database drops what earlier runs recorded for it.
	LeftOut bool
}

// Prober checks one protocol. Probers are tried in order until one succeeds.
type Prober interface {
	Name() Protocol
	Probe(ctx context.Context, d dial.Dialer, p Proxy) (*Result, error)
}

// Check is the endpoint probes reach through a proxy to prove that the proxy
// really forwards traffic. Answering the handshake is not enough: plenty of
// hosts complete a SOCKS negotiation and then drop the payload.
type Check struct {
	Host    string // hostname, so SOCKS5/4a exercise the proxy's own resolver
	Port    uint16 // cleartext port, used by SOCKS and absolute-URI probes
	TLSPort uint16 // used by the HTTP CONNECT probe
	Path    string // requested over the tunnel; a 204 endpoint keeps replies tiny
	Status  int    // the answer that proves the endpoint itself replied; zero means 204
}

// DefaultCheck points at a static endpoint that answers 204 with no body.
var DefaultCheck = Check{
	Host:    "www.gstatic.com",
	Port:    80,
	TLSPort: 443,
	Path:    "/generate_204",
	Status:  204,
}

// status is the only answer that counts. Any other one, even a success or a
// redirect, came from something that is not the endpoint: a login page, an
// interfering middlebox, or a plain web server that is no proxy at all.
func (c Check) status() int {
	if c.Status == 0 {
		return 204
	}
	return c.Status
}

// ErrNotSupported reports that a proxy did not speak the prober's protocol.
// The ladder treats it as "try the next one", not as a hard failure.
var ErrNotSupported = errors.New("protocol not supported by proxy")

// Ladder is the probe order: cheapest and most distinctive handshake first.
func Ladder() []Prober { return LadderFor(DefaultCheck) }

// LadderFor builds the probe order against a specific check endpoint.
//
// SOCKS5 goes first: its greeting is two bytes and the reply is unambiguous.
// SOCKS4 has no method negotiation, so a server that ignores unknown bytes can
// look like it answered; it runs second. HTTP is last because a CONNECT is the
// most expensive handshake and the easiest for an unrelated service to echo.
func LadderFor(c Check) []Prober {
	return []Prober{
		socks5Prober{check: c},
		&socks4Prober{check: c},
		httpProber{check: c},
	}
}

// Detectable is every protocol the ladder can find, in the order it tries them.
func Detectable() []Protocol { return []Protocol{SOCKS5, SOCKS4, HTTPS, HTTP} }

// Linked is every protocol a share link can name.
func Linked() []Protocol { return []Protocol{VLESS, VMess, Trojan, Shadowsocks, Hysteria2} }

// CheckSkip refuses a skip list that names a protocol there is no such thing
// as, or that leaves nothing to find alive.
func CheckSkip(skip []Protocol) error {
	all := slices.Concat(Detectable(), Linked())
	for _, p := range skip {
		if !slices.Contains(all, p) {
			return fmt.Errorf("cannot skip unknown protocol %q, want %s", p, joinProtocols(all))
		}
	}
	left := slices.DeleteFunc(all, func(p Protocol) bool { return slices.Contains(skip, p) })
	if len(left) == 0 {
		return errors.New("every protocol is skipped, so no proxy could be found alive")
	}
	return nil
}

func joinProtocols(ps []Protocol) string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = string(p)
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// LadderSkipping splits the probe order against c in two: the ladder for the
// protocols wanted, and one for the protocols in skip. Both keep the usual
// order. HTTPS and HTTP are the two attempts of one prober, so skipping one of
// them splits that prober between the two ladders.
//
// The skipped ladder is for recognising a proxy that speaks nothing but a
// skipped protocol, so it can be left out rather than recorded dead. Only a
// proxy the wanted ladder found nothing on needs it.
//
// With every classic protocol skipped, the wanted ladder is empty and a
// classic proxy is only ever recognised to be left out. Detect takes an empty
// ladder for the full one, so the caller must not hand it this one.
func LadderSkipping(c Check, skip []Protocol) (wanted, skipped []Prober, err error) {
	if err := CheckSkip(skip); err != nil {
		return nil, nil, err
	}
	add := func(p Protocol, pr Prober) {
		if slices.Contains(skip, p) {
			skipped = append(skipped, pr)
		} else {
			wanted = append(wanted, pr)
		}
	}
	add(SOCKS5, socks5Prober{check: c})
	add(SOCKS4, &socks4Prober{check: c})
	switch https, http := slices.Contains(skip, HTTPS), slices.Contains(skip, HTTP); {
	case https == http: // both attempts on the same side
		add(HTTP, httpProber{check: c})
	default:
		add(HTTPS, httpProber{check: c, noForward: true})
		add(HTTP, httpProber{check: c, noConnect: true})
	}
	return wanted, skipped, nil
}

// Detect runs the ladder against one proxy and returns the first result that
// answered. Each prober gets an equal share of the time left on ctx, so a host
// that accepts TCP and then stalls cannot starve the probers behind it.
func Detect(ctx context.Context, d dial.Dialer, p Proxy, probers []Prober) (*Result, error) {
	if len(probers) == 0 {
		probers = Ladder()
	}
	var attempts []error
	for i, pr := range probers {
		attemptCtx, cancel := withShare(ctx, len(probers)-i)
		res, err := pr.Probe(attemptCtx, d, p)
		cancel()
		if err == nil {
			return res, nil
		}
		attempts = append(attempts, fmt.Errorf("%s: %w", pr.Name(), err))
		if ctx.Err() != nil { // the whole budget is gone; the rest would fail too
			break
		}
	}
	return nil, errors.Join(attempts...)
}

// withShare carves an equal slice of the remaining deadline for one attempt
// out of a total of n.
func withShare(ctx context.Context, n int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok || n <= 1 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Until(deadline)/time.Duration(n))
}

// A SOCKS server answers its first message within a few round trips. A host
// still silent past that is almost surely something else, most often an HTTP
// proxy waiting for the end of a request line that SOCKS bytes never send.
// Each SOCKS attempt used to sit out its whole share of the deadline on such a
// host, leaving the HTTP probe at the bottom of the ladder a third of it: a
// slow HTTP proxy came out dead, or http instead of https.
//
// These are variables so tests can shrink them.
var (
	// minReply is the least a SOCKS attempt waits for its first answer, however
	// close the proxy measured.
	minReply = time.Second
	// upstreamWait is added for SOCKS4, which answers only once it has
	// connected onward to the check host. It covers one lost SYN on that leg.
	upstreamWait = 2 * time.Second
)

// replyRTTs is how many round trips to the proxy a first answer may take.
const replyRTTs = 4

// firstReply is how long a SOCKS attempt waits for the proxy's first answer,
// given how long the TCP handshake to it took.
func firstReply(connectRTT time.Duration) time.Duration {
	return max(minReply, replyRTTs*connectRTT)
}
