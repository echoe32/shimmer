package probe

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testCheck avoids DNS: the fake servers never dial the target anyway, and a
// literal address keeps the SOCKS4 prober off the resolver.
var testCheck = Check{Host: "192.0.2.10", Port: 80, TLSPort: 443, Path: "/generate_204"}

// fakeProxy runs handler on every accepted connection and reports its address.
func fakeProxy(t *testing.T, handler func(net.Conn)) Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handler(c)
			}()
		}
	}()
	return proxyFor(t, ln.Addr())
}

func proxyFor(t *testing.T, addr net.Addr) Proxy {
	t.Helper()
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split %v: %v", addr, err)
	}
	var p uint16
	for _, r := range port {
		p = p*10 + uint16(r-'0')
	}
	return Proxy{Host: host, Port: p}
}

// serveHTTP204 answers one request the way the check endpoint would.
func serveHTTP204(c net.Conn) { serveStatus(c, "204 No Content") }

// serveStatus reads one request and answers it with an empty status-only reply.
func serveStatus(c net.Conn, status string) {
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}
	io.WriteString(c, "HTTP/1.1 "+status+"\r\n\r\n")
}

func socks5Server(c net.Conn) {
	if socks5Handshake(c) {
		serveHTTP204(c)
	}
}

// socks5Handshake grants whatever CONNECT the client asks for.
func socks5Handshake(c net.Conn) bool {
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return false
	}
	if _, err := io.CopyN(io.Discard, c, int64(head[1])); err != nil {
		return false
	}
	c.Write([]byte{0x05, 0x00})

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return false
	}
	switch req[3] {
	case 0x01:
		io.CopyN(io.Discard, c, 4)
	case 0x04:
		io.CopyN(io.Discard, c, 16)
	case 0x03:
		var n [1]byte
		io.ReadFull(c, n[:])
		io.CopyN(io.Discard, c, int64(n[0]))
	}
	io.CopyN(io.Discard, c, 2) // port
	_, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err == nil
}

func socks4Server(c net.Conn) {
	var req [8]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	readUntilNUL(c) // user id
	if req[4] == 0 && req[5] == 0 && req[6] == 0 && req[7] != 0 {
		readUntilNUL(c) // SOCKS4a hostname
	}
	c.Write([]byte{0x00, 0x5A, 0, 0, 0, 0, 0, 0})
	serveHTTP204(c)
}

func readUntilNUL(c net.Conn) {
	var b [1]byte
	for {
		if _, err := io.ReadFull(c, b[:]); err != nil || b[0] == 0 {
			return
		}
	}
}

// httpForwardServer refuses CONNECT and forwards absolute-URI requests, the
// shape of a cleartext-only HTTP proxy.
func httpForwardServer(c net.Conn) {
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimRight(h, "\r\n") == "" {
			break
		}
	}
	if strings.HasPrefix(line, "CONNECT ") {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	if !strings.HasPrefix(line, "GET http://") {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	io.WriteString(c, "HTTP/1.1 204 No Content\r\n\r\n")
}

// ladderDetect runs the ladder the way the pipeline does and reports the first
// protocol that answered.
func ladderDetect(t *testing.T, p Proxy) (Protocol, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := Detect(ctx, &net.Dialer{}, p, LadderFor(testCheck))
	if err != nil {
		return Unknown, err
	}
	if !res.Alive {
		t.Fatal("Detect returned a result that is not alive")
	}
	return res.Protocol, nil
}

func TestLadderDetectsProtocol(t *testing.T) {
	cases := []struct {
		name    string
		handler func(net.Conn)
		want    Protocol
	}{
		{"socks5", socks5Server, SOCKS5},
		{"socks4", socks4Server, SOCKS4},
		{"http", httpForwardServer, HTTP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ladderDetect(t, fakeProxy(t, c.handler))
			if err != nil {
				t.Fatalf("no protocol detected: %v", err)
			}
			if got != c.want {
				t.Errorf("detected %s, want %s", got, c.want)
			}
		})
	}
}

// The wanted ladder never finds a skipped protocol, and the skipped ladder
// does: a proxy that speaks only a skipped protocol can be told from a dead one.
func TestLadderSkippingSplitsProtocols(t *testing.T) {
	cases := []struct {
		name       string
		handler    func(net.Conn)
		skip       []Protocol
		wanted     Protocol // what the wanted ladder finds; Unknown for nothing
		skippedHit bool     // whether the skipped ladder finds anything
	}{
		{"socks5 skipped", socks5Server, []Protocol{SOCKS5}, Unknown, true},
		{"socks4 skipped", socks4Server, []Protocol{SOCKS4}, Unknown, true},
		{"http skipped", httpForwardServer, []Protocol{HTTP}, Unknown, true},
		{"https skipped keeps http", httpForwardServer, []Protocol{HTTPS}, HTTP, false},
		{"others skipped keep socks4", socks4Server, []Protocol{SOCKS5, HTTPS, HTTP}, SOCKS4, false},
	}
	shrink(t, &minReply, 100*time.Millisecond)
	shrink(t, &upstreamWait, 200*time.Millisecond)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wanted, skipped, err := LadderSkipping(testCheck, c.skip)
			if err != nil {
				t.Fatalf("LadderSkipping(%v): %v", c.skip, err)
			}
			p := fakeProxy(t, c.handler)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			res, err := Detect(ctx, &net.Dialer{}, p, wanted)
			switch {
			case c.wanted == Unknown && err == nil:
				t.Errorf("wanted ladder detected %s with %v skipped", res.Protocol, c.skip)
			case c.wanted != Unknown && err != nil:
				t.Errorf("wanted ladder detected nothing: %v", err)
			case c.wanted != Unknown && res.Protocol != c.wanted:
				t.Errorf("wanted ladder detected %s, want %s", res.Protocol, c.wanted)
			}

			ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := Detect(ctx, &net.Dialer{}, p, skipped); (err == nil) != c.skippedHit {
				t.Errorf("skipped ladder found something: %v, want %v (err %v)", err == nil, c.skippedHit, err)
			}
		})
	}
}

// Every prober lands in exactly one of the two ladders, and skipping one HTTP
// attempt splits the HTTP prober between them.
func TestLadderSkippingShape(t *testing.T) {
	cases := []struct {
		skip            []Protocol
		wanted, skipped int
	}{
		{nil, 3, 0},
		{[]Protocol{SOCKS4}, 2, 1},
		{[]Protocol{HTTPS}, 3, 1},
		{[]Protocol{HTTPS, HTTP}, 2, 1},
		{[]Protocol{SOCKS5, SOCKS4, HTTP}, 1, 3},
	}
	for _, c := range cases {
		wanted, skipped, err := LadderSkipping(testCheck, c.skip)
		if err != nil {
			t.Fatalf("LadderSkipping(%v): %v", c.skip, err)
		}
		if len(wanted) != c.wanted || len(skipped) != c.skipped {
			t.Errorf("LadderSkipping(%v) = %d wanted, %d skipped; want %d and %d",
				c.skip, len(wanted), len(skipped), c.wanted, c.skipped)
		}
	}
}

// CONNECT alone reports its failure as such, not as both HTTP attempts.
func TestConnectOnlyReportsConnect(t *testing.T) {
	wanted, _, err := LadderSkipping(testCheck, []Protocol{SOCKS5, SOCKS4, HTTP})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Detect(ctx, &net.Dialer{}, fakeProxy(t, httpForwardServer), wanted)
	if err == nil || !strings.Contains(err.Error(), "CONNECT") || strings.Contains(err.Error(), "absolute-URI") {
		t.Errorf("error %v, want the CONNECT attempt alone", err)
	}
}

func TestLadderSkippingRefusesBadSkips(t *testing.T) {
	for _, skip := range [][]Protocol{
		{"socks6"},
		{Unknown},
		{SOCKS5, SOCKS4, HTTPS, HTTP, VLESS, VMess, Trojan, Shadowsocks, Hysteria2},
	} {
		if wanted, _, err := LadderSkipping(testCheck, skip); err == nil {
			t.Errorf("LadderSkipping(%v) = %d wanted probers, want an error", skip, len(wanted))
		}
	}
}

// Skipping every classic protocol leaves share links to check, and a classic
// proxy only to be recognised and left out.
func TestLadderSkippingEveryClassicProtocol(t *testing.T) {
	wanted, skipped, err := LadderSkipping(testCheck, Detectable())
	if err != nil {
		t.Fatal(err)
	}
	if len(wanted) != 0 || len(skipped) != 3 {
		t.Errorf("got %d wanted and %d skipped probers, want 0 and 3", len(wanted), len(skipped))
	}
}

// Link protocols are accepted in a skip list, and leave the ladder whole.
func TestLadderSkippingLinkProtocols(t *testing.T) {
	wanted, skipped, err := LadderSkipping(testCheck, []Protocol{VLESS, Shadowsocks})
	if err != nil {
		t.Fatal(err)
	}
	if len(wanted) != 3 || len(skipped) != 0 {
		t.Errorf("got %d wanted and %d skipped probers, want 3 and 0", len(wanted), len(skipped))
	}
}

// shrink sets *v to d for the rest of the test.
func shrink(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	saved := *v
	*v = d
	t.Cleanup(func() { *v = saved })
}

// slowForwardServer is an HTTP proxy the way real ones behave towards SOCKS
// bytes: it waits for a request line that never ends. It refuses CONNECT and
// answers an absolute-URI request after delay.
func slowForwardServer(delay time.Duration) func(net.Conn) {
	return func(c net.Conn) {
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		for {
			h, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimRight(h, "\r\n") == "" {
				break
			}
		}
		if strings.HasPrefix(line, "CONNECT ") {
			io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
			return
		}
		time.Sleep(delay)
		io.WriteString(c, "HTTP/1.1 204 No Content\r\n\r\n")
	}
}

// Both SOCKS attempts used to sit out their whole share of the deadline on an
// HTTP proxy, so it had a third of the budget to answer in: this one needs
// half of it and came out dead.
func TestSilentSOCKSAttemptsLeaveHTTPItsTime(t *testing.T) {
	shrink(t, &minReply, 100*time.Millisecond)
	shrink(t, &upstreamWait, 200*time.Millisecond)
	p := fakeProxy(t, slowForwardServer(time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := Detect(ctx, &net.Dialer{}, p, LadderFor(testCheck))
	if err != nil {
		t.Fatalf("live HTTP proxy recorded dead: %v", err)
	}
	if res.Protocol != HTTP {
		t.Errorf("detected %s, want %s", res.Protocol, HTTP)
	}
}

// The cap covers only the proxy's own first answer. A SOCKS5 proxy whose check
// host is slow still has the attempt's whole share for it.
func TestSlowUpstreamIsNotCapped(t *testing.T) {
	shrink(t, &minReply, 100*time.Millisecond)
	p := fakeProxy(t, func(c net.Conn) {
		if socks5Handshake(c) {
			time.Sleep(400 * time.Millisecond)
			serveHTTP204(c)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := (socks5Prober{check: testCheck}).Probe(ctx, &net.Dialer{}, p); err != nil {
		t.Fatalf("SOCKS5 proxy with a slow check host recorded dead: %v", err)
	}
}

// A host that completes the handshake and then says nothing must not count as
// alive: the point of the check request is to catch exactly this.
func TestSilentAfterHandshakeIsNotAlive(t *testing.T) {
	p := fakeProxy(t, func(c net.Conn) {
		var head [2]byte
		io.ReadFull(c, head[:])
		io.CopyN(io.Discard, c, int64(head[1]))
		c.Write([]byte{0x05, 0x00})
		var req [4]byte
		io.ReadFull(c, req[:])
		io.CopyN(io.Discard, c, 4+2)
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		time.Sleep(2 * time.Second) // swallow the request, answer nothing
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := (socks5Prober{check: testCheck}).Probe(ctx, &net.Dialer{}, p); err == nil {
		t.Fatal("silent proxy reported as alive")
	}
}

func TestProbeFailsOnRefusedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := proxyFor(t, ln.Addr())
	ln.Close() // nothing is listening on that port now

	if _, err := ladderDetect(t, p); err == nil {
		t.Fatal("closed port reported as alive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := ConnectRTT(ctx, &net.Dialer{}, p); err == nil {
		t.Fatal("ConnectRTT succeeded against a closed port")
	}
}

func TestConnectRTTMeasuresHandshake(t *testing.T) {
	p := fakeProxy(t, func(net.Conn) {})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rtt, err := ConnectRTT(ctx, &net.Dialer{}, p)
	if err != nil {
		t.Fatalf("ConnectRTT: %v", err)
	}
	if rtt <= 0 || rtt > 2*time.Second {
		t.Errorf("implausible RTT %s", rtt)
	}
}

// Dialer must speak the proxy's protocol on behalf of anything that dials
// through it, which is what the exit-IP lookup relies on.
func TestDialerTunnels(t *testing.T) {
	p := fakeProxy(t, socks5Server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dialer(&net.Dialer{}, p, SOCKS5).DialContext(ctx, "tcp", "192.0.2.10:80")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()
	if err := verifyOrigin(conn, testCheck); err != nil {
		t.Fatalf("tunnelled request failed: %v", err)
	}
}

// countingDialer counts dials and connects nowhere.
type countingDialer struct{ dials atomic.Int64 }

func (c *countingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c.dials.Add(1)
	return nil, errors.New("no network in this test")
}

// A proxy classed HTTP refused CONNECT during the ladder. Tunnelling through it
// used to dial and ask again, spending the exit check's time on a refusal.
func TestDialerDoesNotTunnelThroughHTTP(t *testing.T) {
	d := &countingDialer{}
	p := Proxy{Host: "192.0.2.1", Port: 3128}
	_, err := Dialer(d, p, HTTP).DialContext(context.Background(), "tcp", "192.0.2.10:443")
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("err = %v, want ErrNotSupported", err)
	}
	if n := d.dials.Load(); n != 0 {
		t.Errorf("dialed the proxy %d times to ask for a tunnel it refuses", n)
	}
}

// Only the check endpoint's own answer proves a proxy forwards. A web server
// that redirects everything to https, or a middlebox serving a login page, used
// to pass because any 2xx or 3xx was accepted.
func TestAnswerOtherThanTheEndpointsIsNotAlive(t *testing.T) {
	cases := []struct {
		name    string
		handler func(net.Conn)
	}{
		{"web server redirecting to https", func(c net.Conn) {
			serveStatus(c, "301 Moved Permanently\r\nLocation: https://example.com/")
		}},
		{"web server with a catch-all page", func(c net.Conn) { serveStatus(c, "200 OK") }},
		{"socks5 behind a captive portal", func(c net.Conn) {
			if socks5Handshake(c) {
				serveStatus(c, "302 Found\r\nLocation: http://login.example/")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := ladderDetect(t, fakeProxy(t, c.handler)); err == nil {
				t.Errorf("detected as a working %s proxy", got)
			}
		})
	}
}

// One failed lookup of the check host, even one that failed only because the
// first probe ran out of time, used to push every later SOCKS4 probe of the
// run onto SOCKS4a, which fewer servers speak.
func TestSOCKS4RetriesCheckHostLookup(t *testing.T) {
	fourA := make(chan bool, 3)
	p := fakeProxy(t, func(c net.Conn) {
		var req [8]byte
		if _, err := io.ReadFull(c, req[:]); err != nil {
			return
		}
		readUntilNUL(c) // user id
		is4a := req[4] == 0 && req[5] == 0 && req[6] == 0 && req[7] != 0
		if is4a {
			readUntilNUL(c) // hostname
		}
		fourA <- is4a
		c.Write([]byte{0x00, 0x5A, 0, 0, 0, 0, 0, 0})
		serveHTTP204(c)
	})

	var lookups atomic.Int64
	s := &socks4Prober{
		check: Check{Host: "check.example", Port: 80, Path: "/generate_204"},
		resolve: func(context.Context, string) (netip.Addr, error) {
			if lookups.Add(1) == 1 {
				return netip.Addr{}, errors.New("i/o timeout")
			}
			return netip.MustParseAddr("192.0.2.10"), nil
		},
	}
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := s.Probe(ctx, &net.Dialer{}, p)
		cancel()
		if err != nil {
			t.Fatalf("Probe: %v", err)
		}
	}

	close(fourA)
	var got []bool
	for v := range fourA {
		got = append(got, v)
	}
	if want := []bool{true, false, false}; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("SOCKS4a used per probe = %v, want %v", got, want)
	}
	if n := lookups.Load(); n != 2 {
		t.Errorf("%d lookups, want 2: retried after the failure, kept after the success", n)
	}
}

// junk is an endless stream with no newline in it.
type junk struct{}

func (junk) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 'A'
	}
	return len(b), nil
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += n
	return n, err
}

// A peer that streams bytes with no newline must cost one buffer, not all it
// can send before the deadline.
func TestHeadReadsAreBounded(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		read   func(*bufio.Reader) error
	}{
		{"status line", "", func(br *bufio.Reader) error { _, err := readStatus(br); return err }},
		{"header", "X-Junk: ", drainHeaders},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				io.WriteString(server, c.prefix)
				io.Copy(server, io.LimitReader(junk{}, 1<<20))
			}()
			cr := &countingReader{r: client}
			err := c.read(bufio.NewReader(cr))
			client.Close()

			if err == nil {
				t.Fatal("a line with no end was accepted")
			}
			if cr.n > 64<<10 {
				t.Errorf("read %d bytes of one line before giving up", cr.n)
			}
		})
	}
}
