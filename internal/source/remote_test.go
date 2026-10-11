package source

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shimmer/internal/probe"
)

func collect(t *testing.T, s Source) []probe.Proxy {
	t.Helper()
	ch, err := s.Proxies(context.Background())
	if err != nil {
		t.Fatalf("Proxies: %v", err)
	}
	var got []probe.Proxy
	for p := range ch {
		got = append(got, p)
	}
	return got
}

func TestURLsStreamsEveryList(t *testing.T) {
	var inflight, peak atomic.Int64
	// Every request waits for a second one to arrive before answering. An
	// instant answer let the first download finish before the next began, so
	// a source that does fetch concurrently still showed a peak of 1. One that
	// fetches one at a time waits out the fallback on every list, and fails
	// the peak check below.
	overlap := make(chan struct{})
	var overlapped sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		defer inflight.Add(-1)

		if n >= 2 {
			overlapped.Do(func() { close(overlap) })
		}
		select {
		case <-overlap:
		case <-time.After(time.Second):
		case <-r.Context().Done():
		}

		switch r.URL.Path {
		case "/a":
			fmt.Fprint(w, "# list a\n1.1.1.1:80\n2.2.2.2:1080\n")
		case "/b":
			fmt.Fprint(w, "socks5://3.3.3.3:1080\nbroken\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u := FromURLs([]string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/missing"})
	u.Fetch = 3
	got := collect(t, u)

	if len(got) != 3 {
		t.Fatalf("got %d proxies, want 3: %v", len(got), got)
	}
	if u.Skipped() != 1 {
		t.Errorf("Skipped = %d, want 1", u.Skipped())
	}
	// The 404 list is reported, but the proxies from the others survive it.
	err := u.Err()
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("Err = %v, want the 404 list reported", err)
	}
	if peak.Load() < 2 {
		t.Errorf("lists were fetched one at a time (peak %d)", peak.Load())
	}
}

func TestOpenURLs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lists.txt")
	body := "# mirrors\nhttps://example.com/a.txt\n\nhttp://example.org/b.txt # backup\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	u, err := OpenURLs(path)
	if err != nil {
		t.Fatalf("OpenURLs: %v", err)
	}
	if len(u.urls) != 2 || u.urls[1] != "http://example.org/b.txt" {
		t.Errorf("parsed %v, want the two URLs without the comment", u.urls)
	}

	marked := filepath.Join(dir, "marked.txt")
	os.WriteFile(marked, []byte("\uFEFFhttps://example.com/a.txt\n"), 0o600)
	if u, err := OpenURLs(marked); err != nil {
		t.Errorf("a file saved with a byte-order mark was refused: %v", err)
	} else if u.urls[0] != "https://example.com/a.txt" {
		t.Errorf("parsed %q, want the URL without the mark", u.urls[0])
	}

	bad := filepath.Join(dir, "bad.txt")
	os.WriteFile(bad, []byte("1.2.3.4:8080\n"), 0o600)
	if _, err := OpenURLs(bad); err == nil {
		t.Error("a file of proxies was accepted as a file of list URLs")
	}
	empty := filepath.Join(dir, "empty.txt")
	os.WriteFile(empty, []byte("# nothing\n"), 0o600)
	if _, err := OpenURLs(empty); err == nil {
		t.Error("an empty list file was accepted")
	}
}

func TestURLsStopsOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := range buffer * 4 {
			fmt.Fprintf(w, "10.0.0.1:%d\n", 1024+i%1000)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	u := FromURLs([]string{srv.URL})
	ch, err := u.Proxies(ctx)
	if err != nil {
		t.Fatalf("Proxies: %v", err)
	}
	<-ch
	cancel()
	for range ch { //nolint:revive // draining
	}
	if u.Read() >= int64(buffer*4) {
		t.Errorf("read every line (%d) despite cancellation", u.Read())
	}
	// An interrupt used to be reported as a list that could not be read.
	if err := u.Err(); err != nil {
		t.Errorf("Err = %v, want none: the list did not fail, the run was stopped", err)
	}
}

// A list is read only as fast as its proxies are checked. Time the consumer
// spends catching up must not count against the download: a whole-download
// timeout used to cut off the tail of every big list.
func TestURLsSurvivesSlowConsumer(t *testing.T) {
	const lines = 5000
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := range lines {
			fmt.Fprintf(w, "10.0.%d.%d:8080\n", i/250, i%250+1)
		}
	}))
	defer srv.Close()

	u := FromURLs([]string{srv.URL})
	u.Idle = 100 * time.Millisecond
	ch, err := u.Proxies(context.Background())
	if err != nil {
		t.Fatalf("Proxies: %v", err)
	}
	got := 0
	for range ch {
		got++
		if got == 1 || got == lines/2 {
			time.Sleep(4 * u.Idle) // the probes are slow today
		}
	}
	if got != lines {
		t.Errorf("got %d proxies, want %d", got, lines)
	}
	if err := u.Err(); err != nil {
		t.Errorf("Err = %v, want none", err)
	}
}

func TestURLsGivesUpOnStalledServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "1.1.1.1:80\n")
		w.(http.Flusher).Flush()
		select { // then nothing, until the client gives up
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()

	u := FromURLs([]string{srv.URL})
	u.Idle = 100 * time.Millisecond
	start := time.Now()
	got := collect(t, u)

	if len(got) != 1 {
		t.Errorf("got %d proxies, want the 1 sent before the stall", len(got))
	}
	if err := u.Err(); err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Errorf("Err = %v, want the stall reported", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %s to notice a stalled server", elapsed)
	}
}
