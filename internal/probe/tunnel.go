package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"shimmer/internal/dial"
)

// userAgent is sent on every check request. A recognisable agent is friendlier
// to the endpoint operator than a blank one.
const userAgent = "shimmer-proxy-check/1.0"

// dialProxy opens the TCP connection to the proxy itself and reports how long
// the handshake took.
func dialProxy(ctx context.Context, d dial.Dialer, p Proxy) (net.Conn, time.Duration, error) {
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", p.Addr())
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, err
	}
	return conn, rtt, nil
}

// guard ties a connection's lifetime to ctx: the context deadline becomes the
// socket deadline (none, when ctx has none), and a cancellation unblocks
// whatever read or write is in flight. The returned func releases the watcher
// goroutine and waits for it, so once it returns this guard no longer touches
// c and cannot overwrite the deadline of a guard that follows it.
func guard(ctx context.Context, c net.Conn) func() {
	dl, _ := ctx.Deadline()
	_ = c.SetDeadline(dl)
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			_ = c.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() {
		close(done)
		<-exited
	}
}

// exchange runs fn, one request and its reply, on c under a cap of its own
// within ctx's deadline. A proxy still silent when only the cap has run out
// does not speak the protocol, and is reported as such.
func exchange(ctx context.Context, c net.Conn, within time.Duration, fn func(net.Conn) error) error {
	capped, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	release := guard(capped, c)
	err := fn(c)
	release()
	if err != nil && ctx.Err() == nil && errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("%w: no answer within %s", ErrNotSupported, within)
	}
	return err
}

// socks5Connect performs the greeting, method negotiation and CONNECT of
// RFC 1928 on an already-open connection.
func socks5Connect(c net.Conn, host string, port uint16) error {
	if err := socks5Greet(c); err != nil {
		return err
	}
	return socks5Request(c, host, port)
}

// socks5Greet offers the one method this program speaks and checks that the
// proxy accepts it. The proxy answers this alone, with nothing upstream to
// wait for.
func socks5Greet(c net.Conn) error {
	// Greeting: version 5, one method offered, "no authentication".
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("%w: socks5 greeting answered with version %#x", ErrNotSupported, reply[0])
	}
	switch reply[1] {
	case 0x00: // no authentication required
	case 0xFF:
		return fmt.Errorf("%w: socks5 requires authentication", ErrNotSupported)
	default:
		return fmt.Errorf("%w: socks5 selected method %#x", ErrNotSupported, reply[1])
	}
	return nil
}

// socks5Request asks a greeted proxy to CONNECT to host:port and consumes its
// reply, so the stream starts at the payload.
func socks5Request(c net.Conn, host string, port uint16) error {
	req := []byte{0x05, 0x01, 0x00} // version, CONNECT, reserved
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			v4 := addr.As4()
			req = append(req, 0x01)
			req = append(req, v4[:]...)
		} else {
			v6 := addr.As16()
			req = append(req, 0x04)
			req = append(req, v6[:]...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("hostname too long for socks5: %d bytes", len(host))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}

	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("%w: socks5 reply version %#x", ErrNotSupported, head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 connect refused: %s", socks5Status(head[1]))
	}
	// Drain the bound address so the stream starts at the payload.
	switch head[3] {
	case 0x01:
		_, err := io.CopyN(io.Discard, c, 4+2)
		return err
	case 0x04:
		_, err := io.CopyN(io.Discard, c, 16+2)
		return err
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return err
		}
		_, err := io.CopyN(io.Discard, c, int64(n[0])+2)
		return err
	default:
		return fmt.Errorf("%w: socks5 reply address type %#x", ErrNotSupported, head[3])
	}
}

func socks5Status(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "code " + strconv.Itoa(int(code))
	}
}

// socks4Connect performs a SOCKS4 CONNECT (RFC 1928's predecessor). When ip is
// unset the request falls back to SOCKS4a, which carries the hostname after the
// user id and is understood by fewer servers.
func socks4Connect(c net.Conn, host string, port uint16, ip netip.Addr) error {
	req := []byte{0x04, 0x01, byte(port >> 8), byte(port)}
	socks4a := !ip.IsValid()
	if socks4a {
		req = append(req, 0x00, 0x00, 0x00, 0x01) // 0.0.0.x marks SOCKS4a
	} else {
		v4 := ip.As4()
		req = append(req, v4[:]...)
	}
	req = append(req, 0x00) // empty user id
	if socks4a {
		req = append(req, host...)
		req = append(req, 0x00)
	}
	if _, err := c.Write(req); err != nil {
		return err
	}

	var reply [8]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return err
	}
	if reply[0] != 0x00 {
		return fmt.Errorf("%w: socks4 reply version %#x", ErrNotSupported, reply[0])
	}
	if reply[1] != 0x5A { // 90: request granted
		return fmt.Errorf("socks4 connect refused: %s", socks4Status(reply[1]))
	}
	return nil
}

func socks4Status(code byte) string {
	switch code {
	case 0x5B:
		return "request rejected or failed"
	case 0x5C:
		return "identd unreachable"
	case 0x5D:
		return "identd rejected the user id"
	default:
		return "code " + strconv.Itoa(int(code))
	}
}

// httpConnect opens a CONNECT tunnel through an HTTP proxy.
func httpConnect(c net.Conn, host string, port uint16) error {
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	req := "CONNECT " + target + " HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Proxy-Connection: keep-alive\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return err
	}
	br := bufio.NewReader(c)
	code, err := readStatus(br)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("%w: CONNECT answered %d", ErrNotSupported, code)
	}
	if err := drainHeaders(br); err != nil {
		return err
	}
	if br.Buffered() > 0 {
		return fmt.Errorf("proxy sent %d bytes of payload before the tunnel opened", br.Buffered())
	}
	return nil
}

// readStatus reads one HTTP status line and returns its code.
func readStatus(br *bufio.Reader) (int, error) {
	line, err := readLine(br)
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(line, "HTTP/1.") {
		return 0, fmt.Errorf("%w: not an HTTP response: %q", ErrNotSupported, truncate(line, 64))
	}
	fields := strings.SplitN(line, " ", 3)
	if len(fields) < 2 {
		return 0, fmt.Errorf("%w: malformed status line: %q", ErrNotSupported, truncate(line, 64))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("%w: malformed status code: %q", ErrNotSupported, fields[1])
	}
	return code, nil
}

// drainHeaders consumes header lines up to and including the blank line.
func drainHeaders(br *bufio.Reader) error {
	for {
		line, err := readLine(br)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
}

// readLine reads one line of an HTTP head, without its line ending. It holds
// no more than br's buffer: a peer that streams bytes with no newline gets an
// error once that fills, not as much memory as it can send before the
// deadline.
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", fmt.Errorf("%w: line longer than %d bytes", ErrNotSupported, br.Size())
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// verifyOrigin sends a request over an established tunnel and checks that the
// real endpoint answered. A proxy that completes its handshake and then drops
// the payload fails here, which is the point of sending anything at all.
//
// The request does not ask for the connection to be closed; the caller hangs
// up once it has the status. Asked to close, the endpoint ends the stream right
// behind its answer, a share link's server passes that on as a WebSocket close
// frame, and Xray, taking the frame for a failed outbound, throws away what the
// probe has not read yet. A working WebSocket link came out dead that way, the
// more often the busier the run.
func verifyOrigin(c net.Conn, chk Check) error {
	req := "GET " + chk.Path + " HTTP/1.1\r\n" +
		"Host: " + chk.Host + "\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Accept: */*\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return err
	}
	code, err := readStatus(bufio.NewReader(c))
	if err != nil {
		return err
	}
	if want := chk.status(); code != want {
		return fmt.Errorf("check request answered %d through the proxy, want %d", code, want)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// proxyDialer tunnels every connection through one proxy with a known
// protocol. It satisfies dial.Dialer, so anything that dials (the exit-IP
// lookup, say) can run through a checked proxy unchanged.
type proxyDialer struct {
	base  dial.Dialer
	proxy Proxy
	proto Protocol
}

// Dialer wraps base so that connections are tunnelled through p, which must
// already be known to speak proto. A proxy classed HTTP cannot tunnel: that
// class means it refused CONNECT.
func Dialer(base dial.Dialer, p Proxy, proto Protocol) dial.Dialer {
	return proxyDialer{base: base, proxy: p, proto: proto}
}

func (pd proxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("proxy dialer supports tcp only, got %q", network)
	}
	switch pd.proto {
	case SOCKS5, SOCKS4, HTTPS:
	case HTTP:
		// Asking again would spend whatever time is left on the same refusal.
		return nil, fmt.Errorf("%w: http proxy %s refused CONNECT, so it cannot tunnel", ErrNotSupported, pd.proxy)
	default:
		return nil, fmt.Errorf("cannot tunnel through protocol %q", pd.proto)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	port := uint16(port64)

	conn, _, err := dialProxy(ctx, pd.base, pd.proxy)
	if err != nil {
		return nil, err
	}
	release := guard(ctx, conn)

	switch pd.proto {
	case SOCKS5:
		err = socks5Connect(conn, host, port)
	case SOCKS4:
		ip, rerr := resolve4(ctx, host)
		if rerr != nil {
			err = socks4Connect(conn, host, port, netip.Addr{}) // SOCKS4a
		} else {
			err = socks4Connect(conn, host, port, ip)
		}
	case HTTPS:
		err = httpConnect(conn, host, port)
	}
	if err != nil {
		release()
		conn.Close()
		return nil, err
	}
	// The caller owns the connection now, so hand back its own deadline too.
	release()
	_ = conn.SetDeadline(time.Time{})
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return conn, nil
}

// resolve4 finds an IPv4 address for host, which plain SOCKS4 requires.
func resolve4(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			return addr, nil
		}
		return netip.Addr{}, fmt.Errorf("socks4 needs an IPv4 address, got %s", addr)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no IPv4 address for %s", host)
	}
	return addrs[0].Unmap(), nil
}
