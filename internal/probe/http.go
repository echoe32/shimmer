package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"shimmer/internal/dial"
)

// httpProber covers both HTTP CONNECT tunnelling and plain absolute-URI
// forwarding; which one worked decides HTTPS vs HTTP.
type httpProber struct {
	check Check

	noConnect bool // HTTPS is skipped: no CONNECT attempt
	noForward bool // HTTP is skipped: no absolute-URI attempt
}

func (httpProber) Name() Protocol { return HTTP }

func (h httpProber) Probe(ctx context.Context, d dial.Dialer, p Proxy) (*Result, error) {
	// With one attempt skipped, the other has all the time there is.
	switch {
	case h.noForward:
		res, err := h.probeConnect(ctx, d, p)
		if err != nil {
			return nil, fmt.Errorf("CONNECT: %w", err)
		}
		return res, nil
	case h.noConnect:
		res, err := h.probeForward(ctx, d, p)
		if err != nil {
			return nil, fmt.Errorf("absolute-URI: %w", err)
		}
		return res, nil
	}

	// Two independent attempts, so each gets half of what is left rather than
	// the first one spending it all.
	connectCtx, cancel := withShare(ctx, 2)
	res, connectErr := h.probeConnect(connectCtx, d, p)
	cancel()
	if connectErr == nil {
		return res, nil
	}
	res, fwdErr := h.probeForward(ctx, d, p)
	if fwdErr == nil {
		return res, nil
	}
	// CONNECT is the more common capability, so report its failure first.
	return nil, fmt.Errorf("CONNECT: %w; absolute-URI: %v", connectErr, fwdErr)
}

// probeConnect opens a CONNECT tunnel and speaks TLS to the check endpoint
// through it. A real tunnel carries the handshake; an interfering middlebox
// does not.
func (h httpProber) probeConnect(ctx context.Context, d dial.Dialer, p Proxy) (*Result, error) {
	start := time.Now()
	conn, connectRTT, err := dialProxy(ctx, d, p)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer guard(ctx, conn)()

	if err := httpConnect(conn, h.check.Host, h.check.TLSPort); err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: h.check.Host})
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS through tunnel: %w", err)
	}
	if err := verifyOrigin(tlsConn, h.check); err != nil {
		return nil, err
	}
	return &Result{
		Proxy:      p,
		Protocol:   HTTPS,
		Alive:      true,
		ConnectRTT: connectRTT,
		TotalRTT:   time.Since(start),
		CheckedAt:  time.Now(),
	}, nil
}

// probeForward asks the proxy to fetch an absolute URI, the cleartext-only
// mode of an HTTP proxy.
func (h httpProber) probeForward(ctx context.Context, d dial.Dialer, p Proxy) (*Result, error) {
	start := time.Now()
	conn, connectRTT, err := dialProxy(ctx, d, p)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer guard(ctx, conn)()

	host := h.check.Host
	if h.check.Port != 80 {
		host = net.JoinHostPort(host, strconv.Itoa(int(h.check.Port)))
	}
	req := "GET http://" + host + h.check.Path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Accept: */*\r\n" +
		"Proxy-Connection: close\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	code, err := readStatus(bufio.NewReader(conn))
	if err != nil {
		return nil, err
	}
	if want := h.check.status(); code != want {
		return nil, fmt.Errorf("%w: absolute-URI request answered %d, want %d", ErrNotSupported, code, want)
	}
	return &Result{
		Proxy:      p,
		Protocol:   HTTP,
		Alive:      true,
		ConnectRTT: connectRTT,
		TotalRTT:   time.Since(start),
		CheckedAt:  time.Now(),
	}, nil
}
