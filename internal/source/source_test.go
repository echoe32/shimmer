package source

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"shimmer/internal/probe"
)

func TestParse(t *testing.T) {
	cases := []struct {
		line string
		want probe.Proxy
	}{
		{"1.2.3.4:8080", probe.Proxy{Host: "1.2.3.4", Port: 8080}},
		{"  1.2.3.4:8080  ", probe.Proxy{Host: "1.2.3.4", Port: 8080}},
		{"socks5://1.2.3.4:1080", probe.Proxy{Host: "1.2.3.4", Port: 1080}},
		{"SOCKS4://1.2.3.4:1080", probe.Proxy{Host: "1.2.3.4", Port: 1080}},
		{"https://1.2.3.4:8443", probe.Proxy{Host: "1.2.3.4", Port: 8443}},
		{"http://user:pass@1.2.3.4:3128", probe.Proxy{Host: "1.2.3.4", Port: 3128}},
		{"1.2.3.4:8080:user:pass", probe.Proxy{Host: "1.2.3.4", Port: 8080}},
		{"1.2.3.4 8080", probe.Proxy{Host: "1.2.3.4", Port: 8080}},
		{"1.2.3.4,8080", probe.Proxy{Host: "1.2.3.4", Port: 8080}},
		{"proxy.example.com:3128", probe.Proxy{Host: "proxy.example.com", Port: 3128}},
		{"[2001:db8::1]:1080", probe.Proxy{Host: "2001:db8::1", Port: 1080}},
		{"1.2.3.4:8080 # scraped", probe.Proxy{Host: "1.2.3.4", Port: 8080}},
		{"my_proxy-1.example.com:8080", probe.Proxy{Host: "my_proxy-1.example.com", Port: 8080}},
		// A file saved with a byte-order mark: the mark used to join the host.
		{"\uFEFF1.2.3.4:8080", probe.Proxy{Host: "1.2.3.4", Port: 8080}},
		{strings.Repeat("a", maxHost) + ":80", probe.Proxy{Host: strings.Repeat("a", maxHost), Port: 80}},
	}
	for _, c := range cases {
		got, err := Parse(c.line)
		if err != nil {
			t.Errorf("Parse(%q) failed: %v", c.line, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// A share link keeps what it carries, and its "#" starts a name, not a
// comment.
func TestParseLink(t *testing.T) {
	const line = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.7:443?security=none&type=ws#name # not a comment"
	got, err := Parse("\uFEFF" + line + "  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "203.0.113.7" || got.Port != 443 || got.Link == nil {
		t.Fatalf("got %+v", got)
	}
	if got.Link.Name != "name # not a comment" || got.Link.Raw != line {
		t.Errorf("name %q, raw %q", got.Link.Name, got.Link.Raw)
	}
	for _, bad := range []string{
		"vless://203.0.113.7:443",               // no id
		"ss://YWVzLTI1Ni1jZmI6cHc@1.2.3.4:8388", // aes-256-cfb, a stream cipher
		"trojan://pw@1.2.3.4:443?type=quic",     // transport Xray removed
	} {
		if p, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", bad, p)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, line := range []string{
		"", "   ", "# comment", "// comment",
		"1.2.3.4", "1.2.3.4:", "1.2.3.4:0", "1.2.3.4:99999", "1.2.3.4:http",
		":8080", "2001:db8::1",
		// Junk that ends in a port is still junk, and a host as long as the
		// line wrote a record too long for resume to read back.
		"<td>1.2.3.4</td>:80", "\"host\":80", strings.Repeat("a", maxHost+1) + ":80",
		// A share link of a kind that is not read is no classic proxy. Without
		// a query to trip over, its server used to be checked as one, and
		// recorded dead.
		"tuic://id:pw@1.2.3.4:443#name", "wireguard://key@1.2.3.4:51820", "ssr://1.2.3.4:8388",
	} {
		if p, err := Parse(line); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", line, p)
		}
	}
}

func TestLinesStream(t *testing.T) {
	in := strings.Join([]string{
		"# a list",
		"1.1.1.1:80",
		"",
		"not-a-proxy",
		"2.2.2.2:1080",
	}, "\n")

	l := FromReader(strings.NewReader(in))
	ch, err := l.Proxies(context.Background())
	if err != nil {
		t.Fatalf("Proxies: %v", err)
	}
	var got []probe.Proxy
	for p := range ch {
		got = append(got, p)
	}
	if len(got) != 2 {
		t.Fatalf("got %d proxies, want 2: %v", len(got), got)
	}
	if l.Skipped() != 1 {
		t.Errorf("Skipped = %d, want 1", l.Skipped())
	}
	if l.Read() != 5 {
		t.Errorf("Read = %d, want 5", l.Read())
	}
	if err := l.Err(); err != nil {
		t.Errorf("Err = %v", err)
	}
}

// A line too long to be a proxy is one bad line. It used to end the scan with
// bufio.ErrTooLong, and every proxy after it went unchecked.
func TestLinesSkipsOverlongLine(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     int
	}{
		{"middle", "1.1.1.1:80\n" + strings.Repeat("x", 3*maxLine) + "\n2.2.2.2:80\r\n3.3.3.3:80", 3},
		{"last, unterminated", "1.1.1.1:80\n" + strings.Repeat("x", 2*maxLine), 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := FromReader(strings.NewReader(c.in))
			ch, err := l.Proxies(context.Background())
			if err != nil {
				t.Fatalf("Proxies: %v", err)
			}
			var got int
			for range ch {
				got++
			}
			if got != c.want {
				t.Errorf("got %d proxies, want %d", got, c.want)
			}
			if l.Skipped() != 1 {
				t.Errorf("Skipped = %d, want 1", l.Skipped())
			}
			if l.Read() != int64(c.want+1) {
				t.Errorf("Read = %d, want %d", l.Read(), c.want+1)
			}
			if err := l.Err(); err != nil {
				t.Errorf("Err = %v, want none", err)
			}
		})
	}
}

// cutOff reads like r, except that it fails where r ends.
type cutOff struct {
	r   io.Reader
	err error
}

func (c *cutOff) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == io.EOF {
		err = c.err
	}
	return n, err
}

// A download cut in the middle of a line leaves part of an entry behind. It
// used to be read as a whole one: "5.6.7.8:8080" cut after "80" was checked,
// and recorded, as the proxy 5.6.7.8:80.
func TestLinesDropsLineCutByFailedRead(t *testing.T) {
	reset := errors.New("connection reset by peer")
	l := FromReader(&cutOff{r: strings.NewReader("1.1.1.1:80\n5.6.7.8:80"), err: reset})
	ch, err := l.Proxies(context.Background())
	if err != nil {
		t.Fatalf("Proxies: %v", err)
	}
	var got []probe.Proxy
	for p := range ch {
		got = append(got, p)
	}
	if len(got) != 1 || got[0].Host != "1.1.1.1" {
		t.Errorf("got %v, want the one whole line", got)
	}
	if l.Read() != 1 || l.Skipped() != 0 {
		t.Errorf("Read = %d, Skipped = %d; want 1 and 0: the cut line is not a line", l.Read(), l.Skipped())
	}
	if err := l.Err(); !errors.Is(err, reset) {
		t.Errorf("Err = %v, want the failed read", err)
	}

	// An input that simply ends without a newline still gives its last line.
	l = FromReader(strings.NewReader("1.1.1.1:80\n5.6.7.8:80"))
	if ch, err = l.Proxies(context.Background()); err != nil {
		t.Fatalf("Proxies: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 2 {
		t.Errorf("got %d proxies from an unterminated list, want 2", n)
	}
}

func TestLinesStopsOnCancel(t *testing.T) {
	// More lines than the channel buffer, so the producer is still running
	// when the context is cancelled.
	var b strings.Builder
	for i := range buffer * 4 {
		b.WriteString("1.1.1.1:")
		b.WriteString(string(rune('0'+i%10)) + "0\n")
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := FromReader(strings.NewReader(b.String()))
	ch, err := l.Proxies(ctx)
	if err != nil {
		t.Fatalf("Proxies: %v", err)
	}
	<-ch // let the producer fill the buffer
	cancel()
	for range ch { //nolint:revive // draining until the producer notices
	}
	if l.Read() >= int64(buffer*4) {
		t.Errorf("producer read every line (%d) despite cancellation", l.Read())
	}
}
