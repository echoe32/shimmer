package probe

import (
	"context"
	"time"

	"shimmer/internal/dial"
)

// SOCKS5 greeting + method negotiation, then CONNECT to the check endpoint.
type socks5Prober struct{ check Check }

func (socks5Prober) Name() Protocol { return SOCKS5 }

func (s socks5Prober) Probe(ctx context.Context, d dial.Dialer, p Proxy) (*Result, error) {
	start := time.Now()
	conn, connectRTT, err := dialProxy(ctx, d, p)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Only the greeting is capped: past it the proxy is known to speak SOCKS5,
	// and a slow check host is its upstream's doing, not a wrong protocol.
	if err := exchange(ctx, conn, firstReply(connectRTT), socks5Greet); err != nil {
		return nil, err
	}
	defer guard(ctx, conn)()

	if err := socks5Request(conn, s.check.Host, s.check.Port); err != nil {
		return nil, err
	}
	if err := verifyOrigin(conn, s.check); err != nil {
		return nil, err
	}
	return &Result{
		Proxy:      p,
		Protocol:   SOCKS5,
		Alive:      true,
		ConnectRTT: connectRTT,
		TotalRTT:   time.Since(start),
		CheckedAt:  time.Now(),
	}, nil
}
