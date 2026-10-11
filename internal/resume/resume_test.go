package resume

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shimmer/internal/probe"
	"shimmer/internal/store"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadMissingFileResumesFromNothing(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "absent.jsonl"), "jsonl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0", s.Len())
	}
	if s.Has(probe.Proxy{Host: "1.2.3.4", Port: 80}) {
		t.Error("an absent file claims to hold a proxy")
	}
}

func TestLoadJSONLKeepsCompleteRecords(t *testing.T) {
	path := write(t, "r.jsonl", `{"host":"1.2.3.4","port":8080,"alive":true}
{"host":"5.6.7.8","port":1080,"alive":false}

{"host":"9.9.9.9","por`) // killed mid-write

	s, err := Load(path, "jsonl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
	if s.Corrupt() != 1 {
		t.Errorf("Corrupt = %d, want 1", s.Corrupt())
	}
	for _, p := range []probe.Proxy{{Host: "1.2.3.4", Port: 8080}, {Host: "5.6.7.8", Port: 1080}} {
		if !s.Has(p) {
			t.Errorf("%s not recognised as done", p)
		}
	}
	if s.Has(probe.Proxy{Host: "9.9.9.9", Port: 80}) {
		t.Error("the partial record was taken as done; it must be checked again")
	}
	if s.Has(probe.Proxy{Host: "1.2.3.4", Port: 9090}) {
		t.Error("same host, other port treated as done")
	}
}

// Older builds took any host a line held, so one junk line could leave a
// record longer than maxLine. Load used to fail on it, and so did every later
// -resume of that file; now it costs that one record.
func TestLoadJSONLSkipsOverlongRecord(t *testing.T) {
	huge := `{"host":"` + strings.Repeat("a", 2*maxLine) + `","port":80}`
	path := write(t, "r.jsonl", `{"host":"1.2.3.4","port":8080}`+"\n"+
		huge+"\n"+
		`{"host":"5.6.7.8","port":1080}`+"\n")

	s, err := Load(path, "jsonl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want the 2 records around the long one", s.Len())
	}
	if s.Corrupt() != 1 {
		t.Errorf("Corrupt = %d, want 1", s.Corrupt())
	}
	if !s.Has(probe.Proxy{Host: "5.6.7.8", Port: 1080}) {
		t.Error("the record after the long line was not read")
	}
}

func TestLoadCSVSkipsHeader(t *testing.T) {
	path := write(t, "r.csv", `host,port,protocol,alive
1.2.3.4,8080,socks5,true
5.6.7.8,1080,http,false
`)
	s, err := Load(path, "csv")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
	if !s.Has(probe.Proxy{Host: "5.6.7.8", Port: 1080}) {
		t.Error("5.6.7.8:1080 not recognised as done")
	}
	if s.Has(probe.Proxy{Host: "host", Port: 0}) {
		t.Error("the header row was taken as a record")
	}
}

func TestLoadCSVStopsAtPartialRow(t *testing.T) {
	path := write(t, "r.csv", "host,port,protocol\n1.2.3.4,8080,socks5\n5.6.7.8,")
	s, err := Load(path, "csv")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Has(probe.Proxy{Host: "1.2.3.4", Port: 8080}) {
		t.Error("the complete row was lost")
	}
	if s.Has(probe.Proxy{Host: "5.6.7.8", Port: 0}) {
		t.Error("the partial row was taken as done")
	}
}

// Resumed without -format, a CSV file was read as JSONL: every row came out
// unreadable, every proxy was checked again, and JSONL was appended to the CSV.
func TestLoadRefusesFileOfOtherFormat(t *testing.T) {
	for _, c := range []struct{ name, body, format string }{
		{"csv read as jsonl", "host,port,protocol\n1.2.3.4,8080,socks5\n", "jsonl"},
		{"jsonl read as csv", `{"host":"1.2.3.4","port":8080}` + "\n", "csv"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load(write(t, "results", c.body), c.format); err == nil {
				t.Error("Load accepted a file in the other format")
			}
		})
	}
}

func TestHostCaseDoesNotMatter(t *testing.T) {
	path := write(t, "r.jsonl", `{"host":"Proxy.Example.COM","port":3128}`+"\n")
	s, err := Load(path, "jsonl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Has(probe.Proxy{Host: "proxy.example.com", Port: 3128}) {
		t.Error("the same host spelled differently was not recognised")
	}
}

func TestFilterDropsOnlyWhatIsDone(t *testing.T) {
	path := write(t, "r.jsonl", `{"host":"1.1.1.1","port":80}
{"host":"2.2.2.2","port":80}
`)
	s, err := Load(path, "jsonl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	in := make(chan probe.Proxy, 4)
	for _, p := range []probe.Proxy{
		{Host: "1.1.1.1", Port: 80},
		{Host: "3.3.3.3", Port: 80},
		{Host: "2.2.2.2", Port: 80},
		{Host: "4.4.4.4", Port: 80},
	} {
		in <- p
	}
	close(in)

	var got []string
	for p := range s.Filter(context.Background(), in) {
		got = append(got, p.String())
	}
	if len(got) != 2 || got[0] != "3.3.3.3:80" || got[1] != "4.4.4.4:80" {
		t.Errorf("passed through %v, want the two unchecked proxies", got)
	}
	if s.Skipped() != 2 {
		t.Errorf("Skipped = %d, want 2", s.Skipped())
	}
}

func TestFilterOnEmptySetIsFree(t *testing.T) {
	in := make(chan probe.Proxy)
	s := &Set{seen: map[uint64]struct{}{}}
	if out := s.Filter(context.Background(), in); out != (<-chan probe.Proxy)(in) {
		t.Error("an empty set copied the stream instead of passing it through")
	}
	var nilSet *Set
	if out := nilSet.Filter(context.Background(), in); out != (<-chan probe.Proxy)(in) {
		t.Error("a nil set copied the stream instead of passing it through")
	}
}

func TestNilSetIsSafe(t *testing.T) {
	var s *Set
	if s.Len() != 0 || s.Corrupt() != 0 || s.Skipped() != 0 || s.Has(probe.Proxy{Host: "a", Port: 1}) {
		t.Error("a nil set did not behave as an empty one")
	}
}

func TestFilterStopsOnCancel(t *testing.T) {
	path := write(t, "r.jsonl", `{"host":"1.1.1.1","port":80}`+"\n")
	s, err := Load(path, "jsonl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	in := make(chan probe.Proxy)
	out := s.Filter(ctx, in)
	go func() {
		in <- probe.Proxy{Host: "8.8.8.8", Port: 80} // nobody is reading out
		close(in)
	}()
	cancel()

	for range out { //nolint:revive // draining until Filter gives up
	}
}

// A run killed at any byte of its last record must resume without losing a
// proxy: whatever Load counts as done has to survive the store trimming the
// torn tail, and rows appended afterwards have to read back. A torn row that
// still parsed used to be skipped and then cut away, and a CSV error column
// spanning lines let a torn quote swallow every row appended after it.
func TestResumeAfterKillAtAnyByte(t *testing.T) {
	for _, format := range []string{"jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			first := []probe.Result{
				{Proxy: probe.Proxy{Host: "1.1.1.1", Port: 80}, Alive: true},
				{Proxy: probe.Proxy{Host: "2.2.2.2", Port: 8080}, Err: errors.Join(
					errors.New("socks5: EOF"), errors.New("socks4: EOF"), errors.New("http: EOF"))},
			}
			full := filepath.Join(t.TempDir(), "full")
			writeResults(t, full, format, store.Truncate, first...)
			data, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			lastRow := bytes.LastIndexByte(data[:len(data)-1], '\n') + 1

			for cut := lastRow; cut <= len(data); cut++ {
				path := filepath.Join(t.TempDir(), "r."+format)
				if err := os.WriteFile(path, data[:cut], 0o644); err != nil {
					t.Fatal(err)
				}
				done, err := Load(path, format)
				if err != nil {
					t.Fatalf("cut at %d: Load: %v", cut, err)
				}
				resumed := probe.Proxy{Host: "3.3.3.3", Port: 3128}
				writeResults(t, path, format, store.Append, probe.Result{Proxy: resumed, Alive: true})

				after, err := Load(path, format)
				if err != nil {
					t.Fatalf("cut at %d: reload: %v", cut, err)
				}
				if !after.Has(resumed) {
					t.Errorf("cut at %d: the row appended on resume does not read back", cut)
				}
				for k := range done.seen {
					if _, ok := after.seen[k]; !ok {
						t.Errorf("cut at %d: a proxy taken as done is not in the file", cut)
					}
				}
			}
		})
	}
}

func writeResults(t *testing.T, path, format string, m store.Mode, results ...probe.Result) {
	t.Helper()
	st, err := store.Open(path, format, m)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	for _, r := range results {
		if err := st.Write(context.Background(), r); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
