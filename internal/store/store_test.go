package store

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shimmer/internal/probe"
)

func sample() []probe.Result {
	return []probe.Result{
		{
			Proxy:      probe.Proxy{Host: "1.2.3.4", Port: 1080},
			Protocol:   probe.SOCKS5,
			Alive:      true,
			ConnectRTT: 12 * time.Millisecond,
			TotalRTT:   140 * time.Millisecond,
			ExitIP:     netip.MustParseAddr("5.6.7.8"),
			Country:    "DE",
			ASN:        64500,
			CheckedAt:  time.Unix(1700000000, 0).UTC(),
		},
		{
			Proxy:     probe.Proxy{Host: "9.9.9.9", Port: 3128},
			Protocol:  probe.Unknown,
			Err:       errors.New("dial tcp: connection refused"),
			CheckedAt: time.Unix(1700000001, 0).UTC(),
		},
	}
}

func writeAll(t *testing.T, s Store, results []probe.Result) {
	t.Helper()
	for _, r := range results {
		if err := s.Write(context.Background(), r); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL: %v", err)
	}
	writeAll(t, s, sample())

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), data)
	}

	var first record
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 is not JSON: %v", err)
	}
	if first.Host != "1.2.3.4" || first.Port != 1080 || first.Protocol != "socks5" || !first.Alive {
		t.Errorf("line 1 round-tripped wrong: %+v", first)
	}
	if first.ConnectMS != 12 || first.TotalMS != 140 {
		t.Errorf("durations wrong: connect %v, total %v", first.ConnectMS, first.TotalMS)
	}
	if first.ExitIP != "5.6.7.8" || first.Country != "DE" || first.ASN != 64500 {
		t.Errorf("geo fields wrong: %+v", first)
	}

	var second record
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 2 is not JSON: %v", err)
	}
	if second.Alive || !strings.Contains(second.Error, "connection refused") {
		t.Errorf("dead proxy round-tripped wrong: %+v", second)
	}
	if second.ExitIP != "" {
		t.Errorf("unset exit IP written as %q", second.ExitIP)
	}
}

func TestCSV(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s, err := NewCSV(path)
	if err != nil {
		t.Fatalf("NewCSV: %v", err)
	}
	writeAll(t, s, sample())

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows (with header), want 3", len(rows))
	}
	// The classic columns keep their old places, so older files resume.
	if rows[0][0] != "host" || rows[0][10] != "checked_at" || rows[0][len(rows[0])-1] != "link" {
		t.Errorf("header wrong: %v", rows[0])
	}
	if len(rows[1]) != len(csvHeader) {
		t.Errorf("row 1 has %d fields, header has %d", len(rows[1]), len(csvHeader))
	}
	if rows[1][2] != "socks5" || rows[1][3] != "true" || rows[1][6] != "5.6.7.8" {
		t.Errorf("row 1 wrong: %v", rows[1])
	}
	if rows[2][3] != "false" || !strings.Contains(rows[2][9], "connection refused") {
		t.Errorf("row 2 wrong: %v", rows[2])
	}
}

// A run that is cut short must still leave every buffered result on disk.
func TestCloseFlushesPartialRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL: %v", err)
	}
	for range 3 { // far below flushEvery
		if err := s.Write(context.Background(), sample()[0]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, _ := os.ReadFile(path)
	if n := strings.Count(string(data), "\n"); n != 3 {
		t.Errorf("file holds %d lines, want 3", n)
	}
}

func TestWriteHonoursCancellation(t *testing.T) {
	s, err := NewJSONL(filepath.Join(t.TempDir(), "x.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONL: %v", err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Write(ctx, sample()[0]); !errors.Is(err, context.Canceled) {
		t.Errorf("Write after cancel returned %v, want context.Canceled", err)
	}
}

// The ladder joins its attempts' errors with newlines. Written as they are, a
// CSV row spans several lines, and trimming a torn tail line by line can then
// leave an open quote that swallows everything appended after it.
func TestErrorStaysOnOneLine(t *testing.T) {
	res := probe.Result{
		Proxy: probe.Proxy{Host: "1.2.3.4", Port: 1080},
		Err:   errors.Join(errors.New("socks5: EOF"), errors.New("socks4: EOF"), errors.New("http: EOF")),
	}
	for _, format := range []string{"jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out."+format)
			s, err := Open(path, format, Truncate)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			writeAll(t, s, []probe.Result{res})

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if format == "csv" {
				want = 2 // header and row
			}
			if n := strings.Count(string(data), "\n"); n != want {
				t.Errorf("%d lines, want %d:\n%s", n, want, data)
			}
			if !strings.Contains(string(data), "socks5: EOF; socks4: EOF; http: EOF") {
				t.Errorf("attempts not kept apart on one line:\n%s", data)
			}
		})
	}
}

// A left-out result is no record, whichever file store is handed one.
func TestFileStoresIgnoreLeftOut(t *testing.T) {
	leftOut := probe.Result{
		Proxy:     probe.Proxy{Host: "7.7.7.7", Port: 1080},
		Protocol:  probe.SOCKS4,
		LeftOut:   true,
		CheckedAt: time.Unix(1700000002, 0).UTC(),
	}
	for _, format := range []string{"jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out."+format)
			s, err := Open(path, format, Truncate)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			writeAll(t, s, append(sample(), leftOut))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "7.7.7.7") {
				t.Errorf("left-out proxy written:\n%s", data)
			}
			if !strings.Contains(string(data), "9.9.9.9") {
				t.Errorf("the other results are missing:\n%s", data)
			}
		})
	}
}
