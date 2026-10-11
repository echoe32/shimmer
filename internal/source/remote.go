package source

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shimmer/internal/probe"
)

// defaultFetch is how many lists are downloaded at once. Lists are few and
// large, so a handful of parallel fetches saturates the link without making
// the run look like an attack on whoever hosts them.
const defaultFetch = 4

// A list is read only as fast as its proxies are checked, which for a big list
// takes hours, so nothing limits a whole download. What is limited is how long
// a server may take to start answering, and how long one read may then wait.
const (
	headerTimeout = 30 * time.Second
	defaultIdle   = time.Minute
)

// errStalled marks a list whose server stopped sending part way through.
var errStalled = errors.New("download stalled")

// URLs streams proxies from remote lists. Each list is downloaded and parsed
// as it arrives, so probing starts before the last list has finished.
type URLs struct {
	Client *http.Client  // nil uses a client that bounds the wait for headers, not the download
	Fetch  int           // concurrent downloads; defaultFetch when zero
	Idle   time.Duration // longest one read may wait for data; defaultIdle when zero

	urls    []string
	read    atomic.Int64
	skipped atomic.Int64

	mu   sync.Mutex
	errs []error
}

// OpenURLs reads a text file of list links, one URL per line. Blank lines and
// # comments are ignored, so the same file can carry notes.
func OpenURLs(path string) (*URLs, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), bom))
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			return nil, fmt.Errorf("%s: %q is not an http(s) URL", path, truncate(line))
		}
		urls = append(urls, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("%s holds no list URLs", path)
	}
	return &URLs{urls: urls}, nil
}

// FromURLs streams the given lists.
func FromURLs(urls []string) *URLs { return &URLs{urls: append([]string(nil), urls...)} }

// Proxies downloads every list, several at a time, and streams what parses.
// A list that fails to download is recorded and skipped: one dead mirror
// should not cost the whole run.
func (u *URLs) Proxies(ctx context.Context) (<-chan probe.Proxy, error) {
	client := u.Client
	if client == nil {
		client = newClient()
	}
	fetch := u.Fetch
	if fetch <= 0 {
		fetch = defaultFetch
	}
	if fetch > len(u.urls) {
		fetch = len(u.urls)
	}

	out := make(chan probe.Proxy, buffer)
	links := make(chan string)

	var wg sync.WaitGroup
	wg.Add(fetch)
	for range fetch {
		go func() {
			defer wg.Done()
			for link := range links {
				// Cancellation is the caller's own doing, not a list that failed.
				if err := u.stream(ctx, client, link, out); err != nil && ctx.Err() == nil {
					u.mu.Lock()
					u.errs = append(u.errs, fmt.Errorf("%s: %w", link, err))
					u.mu.Unlock()
				}
				if ctx.Err() != nil {
					return
				}
			}
		}()
	}
	go func() {
		defer close(links)
		for _, link := range u.urls {
			select {
			case links <- link:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()
	return out, nil
}

// newClient waits a bounded time for a server to start answering, and then
// as long as the download takes.
func newClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = headerTimeout
	return &http.Client{Transport: tr}
}

// stream parses one list as it downloads, rather than buffering the body.
func (u *URLs) stream(ctx context.Context, c *http.Client, link string, out chan<- probe.Proxy) error {
	reqCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, link, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "shimmer-proxy-check/1.0")

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("answered %s", resp.Status)
	}

	idle := u.Idle
	if idle <= 0 {
		idle = defaultIdle
	}
	body := &idleReader{r: resp.Body, idle: idle, stall: func() {
		cancel(fmt.Errorf("%w: no data for %s", errStalled, idle))
	}}
	err = feed(ctx, body, out, &u.read, &u.skipped)
	if cause := context.Cause(reqCtx); err != nil && errors.Is(cause, errStalled) {
		return cause
	}
	return err
}

// idleReader calls stall when one Read waits longer than idle. Only the wait
// inside Read counts: time between reads is the probes catching up, not the
// server stalling.
type idleReader struct {
	r     io.Reader
	idle  time.Duration
	stall func()
}

func (i *idleReader) Read(p []byte) (int, error) {
	t := time.AfterFunc(i.idle, i.stall)
	defer t.Stop()
	return i.r.Read(p)
}

// Read is how many lines were consumed across every list.
func (u *URLs) Read() int64 { return u.read.Load() }

// Skipped is how many non-blank lines failed to parse.
func (u *URLs) Skipped() int64 { return u.skipped.Load() }

// Err reports the lists that could not be read. Only meaningful once the
// channel from Proxies has closed.
func (u *URLs) Err() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return errors.Join(u.errs...)
}

// Close exists so callers can treat both sources alike.
func (u *URLs) Close() error { return nil }
