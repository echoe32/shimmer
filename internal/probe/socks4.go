package probe

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"shimmer/internal/dial"
)

// SOCKS4/4a CONNECT request. No method negotiation, so try it after SOCKS5.
type socks4Prober struct {
	check Check

	// SOCKS4 carries a raw IPv4 address, so the check host is resolved once
	// and shared by every probe. SOCKS4a (hostname) is the fallback.
	ip      atomic.Pointer[netip.Addr]
	resolve func(ctx context.Context, host string) (netip.Addr, error) // nil uses resolve4
}

func (*socks4Prober) Name() Protocol { return SOCKS4 }

// checkIP resolves the check host until one lookup succeeds, then keeps that
// answer. A failure is not kept: it may be no more than this probe's deadline
// running out, and it must not send every later probe down the SOCKS4a path.
// The resolver merges concurrent lookups of one host, so a retry costs one
// query, not one per worker.
func (s *socks4Prober) checkIP(ctx context.Context) netip.Addr {
	if ip := s.ip.Load(); ip != nil {
		return *ip
	}
	resolve := s.resolve
	if resolve == nil {
		resolve = resolve4
	}
	ip, err := resolve(ctx, s.check.Host)
	if err != nil {
		return netip.Addr{} // SOCKS4a, for this probe only
	}
	s.ip.Store(&ip)
	return ip
}

func (s *socks4Prober) Probe(ctx context.Context, d dial.Dialer, p Proxy) (*Result, error) {
	ip := s.checkIP(ctx)

	start := time.Now()
	conn, connectRTT, err := dialProxy(ctx, d, p)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// SOCKS4 has no greeting: its first answer comes only once the proxy has
	// connected onward, so the cap allows for that leg too.
	err = exchange(ctx, conn, firstReply(connectRTT)+upstreamWait, func(c net.Conn) error {
		return socks4Connect(c, s.check.Host, s.check.Port, ip)
	})
	if err != nil {
		return nil, err
	}
	defer guard(ctx, conn)()

	if err := verifyOrigin(conn, s.check); err != nil {
		return nil, err
	}
	return &Result{
		Proxy:      p,
		Protocol:   SOCKS4,
		Alive:      true,
		ConnectRTT: connectRTT,
		TotalRTT:   time.Since(start),
		CheckedAt:  time.Now(),
	}, nil
}
