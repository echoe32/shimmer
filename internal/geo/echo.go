package geo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"shimmer/internal/dial"
)

// EchoURL answers with the caller's address and nothing else. HTTPS, so a
// proxy in the middle cannot rewrite the answer it reports about itself.
var EchoURL = "https://api.ipify.org"

// PlainEchoURL is the same answer over cleartext, for HTTP proxies that refuse
// CONNECT and forward only absolute-URI requests. Such a proxy could rewrite
// the answer, but cleartext is the only thing it carries at all.
var PlainEchoURL = "http://api.ipify.org"

// maxEchoBody caps what the echo endpoint can make us read. An address is
// under 50 bytes; anything longer is not an answer we want.
const maxEchoBody = 256

// ExitIP asks an echo endpoint, through the proxy, which address it sees. This
// is the only way to learn the real exit of a chained or relaying proxy, where
// the listening IP and the egress IP differ.
//
// d must already tunnel through the proxy: probe.Dialer builds such a dialer
// from a proxy whose protocol is known.
//
// Keep-alives stay on, though the connection is used once: turned off, the
// request asks the endpoint to close after its answer, and through a share
// link over WebSocket that close can cost the answer itself, as it did the
// check request's (verifyOrigin, in package probe). echo closes the connection
// when it is done.
func ExitIP(ctx context.Context, d dial.Dialer) (netip.Addr, error) {
	return echo(ctx, &http.Transport{
		Proxy:             nil, // the tunnelling lives in d, not in the environment
		DialContext:       d.DialContext,
		ForceAttemptHTTP2: false,
	}, EchoURL)
}

// ExitIPForward asks the echo endpoint through an HTTP proxy that forwards
// absolute-URI requests but will not tunnel. d dials the proxy at proxyAddr
// itself; the request then goes to it as "GET http://...".
func ExitIPForward(ctx context.Context, d dial.Dialer, proxyAddr string) (netip.Addr, error) {
	return echo(ctx, &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		DialContext:       d.DialContext,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
	}, PlainEchoURL)
}

// echo fetches one address from echoURL over tr.
func echo(ctx context.Context, tr *http.Transport, echoURL string) (netip.Addr, error) {
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, echoURL, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", "shimmer-proxy-check/1.0")

	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("echo endpoint answered %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEchoBody))
	if err != nil {
		return netip.Addr{}, err
	}
	text := strings.TrimSpace(string(body))
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("echo endpoint returned %q, not an address", text)
	}
	return addr.Unmap(), nil
}
