// Package source loads proxy candidates from files, stdin or remote lists.
package source

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"shimmer/internal/link"
	"shimmer/internal/probe"
)

// Source yields proxies to check. Implementations stream rather than buffer,
// so a multi-million-line list does not have to fit in memory.
type Source interface {
	Proxies(ctx context.Context) (<-chan probe.Proxy, error)
}

// buffer is how many parsed proxies wait ahead of the workers. Parsing is far
// cheaper than probing, so a small buffer keeps every worker fed.
const buffer = 1024

// maxLine is the longest line read as a proxy. A longer one (a minified page
// served in place of a list, say) is counted as one bad line and skipped; it
// does not end the input.
const maxLine = 1024 * 1024

// Lines streams one proxy per line of text. Blank lines and lines starting
// with # or // are ignored; a line that does not parse is counted and skipped,
// because a single typo in a million-line list should not end the run.
type Lines struct {
	r       io.Reader
	closer  io.Closer
	skipped atomic.Int64
	read    atomic.Int64
	err     atomic.Pointer[error]
}

// Open reads the list at path. The path "-" reads stdin.
func Open(path string) (*Lines, error) {
	if path == "-" || path == "" {
		return &Lines{r: os.Stdin}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &Lines{r: f, closer: f}, nil
}

// FromReader streams a list already open elsewhere.
func FromReader(r io.Reader) *Lines { return &Lines{r: r} }

// Proxies parses the list in the background and streams the results. The
// channel closes when the input ends, when parsing fails, or when ctx is
// cancelled; call Err afterwards to tell those apart.
func (l *Lines) Proxies(ctx context.Context) (<-chan probe.Proxy, error) {
	out := make(chan probe.Proxy, buffer)
	go func() {
		defer close(out)
		// Cancellation is the caller's own doing, not a read failure.
		if err := feed(ctx, l.r, out, &l.read, &l.skipped); err != nil && ctx.Err() == nil {
			l.err.Store(&err)
		}
	}()
	return out, nil
}

// feed parses r into out, one proxy per line, until r ends or ctx is
// cancelled. Every line is counted in read, and every non-blank line that is
// not a proxy in skipped.
func feed(ctx context.Context, r io.Reader, out chan<- probe.Proxy, read, skipped *atomic.Int64) error {
	src := &cutShort{r: r}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	sc.Split(dropCutLine(src, skipLongLines(func() {
		read.Add(1)
		skipped.Add(1)
	})))
	for sc.Scan() {
		read.Add(1)
		p, err := Parse(sc.Text())
		if err != nil {
			if err != errBlank {
				skipped.Add(1)
			}
			continue
		}
		select {
		case out <- p:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return sc.Err()
}

// skipLongLines splits like bufio.ScanLines, except that a line longer than
// maxLine is thrown away and reported through dropped, where ScanLines would
// stop the whole scan with bufio.ErrTooLong.
func skipLongLines(dropped func()) bufio.SplitFunc {
	discarding := false
	return func(data []byte, atEOF bool) (int, []byte, error) {
		if discarding {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				return len(data), nil, nil
			}
			discarding = false
			return i + 1, nil, nil
		}
		advance, token, err := bufio.ScanLines(data, atEOF)
		if advance == 0 && token == nil && len(data) >= maxLine {
			// The buffer is full and holds no newline, so whatever this line
			// is, it is not a proxy. Drop it now, and the rest as it arrives.
			dropped()
			discarding = true
			return len(data), nil, nil
		}
		return advance, token, err
	}
}

// cutShort notes whether its reader failed, rather than ended.
type cutShort struct {
	r      io.Reader
	failed bool
}

func (c *cutShort) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil && err != io.EOF {
		c.failed = true
	}
	return n, err
}

// dropCutLine splits like split, except that the unfinished line a failed read
// leaves behind is thrown away. The scanner hands over whatever it holds when
// a read fails, just as it does where the input ends: a download cut in the
// middle of "5.6.7.8:8080" used to give the proxy 5.6.7.8:80, and a share link
// cut short a link that was never in the list.
func dropCutLine(src *cutShort, split bufio.SplitFunc) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (int, []byte, error) {
		if atEOF && src.failed && bytes.IndexByte(data, '\n') < 0 {
			return len(data), nil, nil
		}
		return split(data, atEOF)
	}
}

// Read is how many lines were consumed so far.
func (l *Lines) Read() int64 { return l.read.Load() }

// Skipped is how many non-blank lines failed to parse.
func (l *Lines) Skipped() int64 { return l.skipped.Load() }

// Err reports a read failure, if any. Only meaningful once the channel from
// Proxies has closed.
func (l *Lines) Err() error {
	if p := l.err.Load(); p != nil {
		return *p
	}
	return nil
}

// Close releases the underlying file, if Lines opened one.
func (l *Lines) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// errBlank marks a line that carries nothing, as opposed to a malformed one.
var errBlank = fmt.Errorf("blank line")

// bom is the byte-order mark some editors put at the start of a text file.
// TrimSpace leaves it alone, and it used to become part of the first host.
const bom = "\uFEFF"

// Parse reads one line into a Proxy: a share link, or a classic proxy's
// "host:port".
//
// A share link (vless://, vmess://, trojan://, ss://, hysteria2://, hy2://)
// keeps everything it carries, since checking it needs its credentials and
// transport. Its "#" starts its name, not a comment.
//
// Real lists of classic proxies are untidy, so these all parse to the same
// proxy:
//
//	1.2.3.4:8080
//	socks5://1.2.3.4:8080
//	user:pass@1.2.3.4:8080          (credentials are dropped, not used)
//	1.2.3.4:8080:user:pass
//	1.2.3.4 8080
//	[2001:db8::1]:8080
//
// A line under any other scheme than a classic proxy's or a share link's is
// refused.
func Parse(line string) (probe.Proxy, error) {
	s := strings.TrimSpace(strings.TrimPrefix(line, bom))
	if link.Is(s) {
		l, err := link.Parse(s)
		if err != nil {
			return probe.Proxy{}, err
		}
		return probe.Proxy{Host: l.Host, Port: l.Port, Link: l}, nil
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" || strings.HasPrefix(s, "//") {
		return probe.Proxy{}, errBlank
	}
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		// Only a classic proxy's scheme is dropped. A share link of a kind
		// that is not read (ssr://, tuic://, ...) names a server too, and with
		// no query to trip over it used to be checked as a classic proxy and
		// recorded dead.
		if !classicSchemes[strings.ToLower(scheme)] {
			return probe.Proxy{}, fmt.Errorf("unsupported scheme in %q", truncate(line))
		}
		s = rest
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 { // credentials, dropped
		s = s[i+1:]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return probe.Proxy{}, fmt.Errorf("no address in %q", truncate(line))
	}
	// "host port" and "host,port" are as common in scraped lists as "host:port".
	if f := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == ';' }); len(f) >= 2 {
		s = f[0] + ":" + f[1]
	}

	host, portStr, err := splitHostPort(s)
	if err != nil {
		return probe.Proxy{}, fmt.Errorf("%w in %q", err, truncate(line))
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return probe.Proxy{}, fmt.Errorf("bad port %q in %q", portStr, truncate(line))
	}
	if host == "" {
		return probe.Proxy{}, fmt.Errorf("no host in %q", truncate(line))
	}
	if !validHost(host) {
		return probe.Proxy{}, fmt.Errorf("bad host in %q", truncate(line))
	}
	return probe.Proxy{Host: host, Port: uint16(port)}, nil
}

// classicSchemes are the prefixes a classic proxy may carry. They are dropped,
// not used as a hint: the protocol is always detected.
var classicSchemes = map[string]bool{
	"http":    true,
	"https":   true,
	"socks":   true,
	"socks4":  true,
	"socks4a": true,
	"socks5":  true,
	"socks5h": true,
}

// maxHost is the longest name DNS allows.
const maxHost = 253

// validHost accepts an IP address, or a name made only of the bytes a DNS name
// may hold. Anything else cannot be dialed, and a line of junk that happened
// to end in ":80" used to become a host as long as the line: its record came
// out longer than resume will read back.
func validHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if len(host) > maxHost {
		return false
	}
	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

// splitHostPort handles the bracketed IPv6 form, the bare "host:port" form,
// and the "host:port:user:pass" form that list vendors like to emit.
func splitHostPort(s string) (host, port string, err error) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", "", fmt.Errorf("unclosed [")
		}
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("missing port")
		}
		return s[1:end], firstField(rest[1:]), nil
	}
	parts := strings.Split(s, ":")
	switch {
	case len(parts) == 2:
		return parts[0], parts[1], nil
	case len(parts) > 2:
		// Either an unbracketed IPv6 address, or host:port with trailing
		// credentials. Only the former parses as an address.
		if _, e := netip.ParseAddr(s); e == nil {
			return "", "", fmt.Errorf("IPv6 address without a port")
		}
		if _, e := netip.ParseAddr(strings.Join(parts[:len(parts)-1], ":")); e == nil {
			return strings.Join(parts[:len(parts)-1], ":"), parts[len(parts)-1], nil
		}
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("missing port")
	}
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 48 {
		return s
	}
	return s[:48] + "..."
}
