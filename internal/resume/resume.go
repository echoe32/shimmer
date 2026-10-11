// Package resume lets an interrupted run continue where it stopped, by reading
// back the results file the previous run already wrote.
//
// The results file is the checkpoint: there is no separate state to keep in
// sync with it, and a file written by an older run of the same format resumes
// just as well as one this build produced.
//
// One consequence is worth knowing: a run started with -alive-only wrote no
// record for the proxies that were dead, so resuming such a run re-checks
// them. Resume is exact only for a file that holds every result.
package resume

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"shimmer/internal/link"
	"shimmer/internal/probe"
	"shimmer/internal/store"
)

// Set is the proxies a previous run already recorded.
//
// Entries are 64-bit hashes, not strings: a resumed run over a multi-million
// line list would otherwise hold hundreds of megabytes of text it never reads
// back. A collision costs one proxy that is not re-checked, which at 64 bits
// over lists of this size is not expected to happen.
type Set struct {
	seen    map[uint64]struct{}
	corrupt int
	skipped atomic.Int64
}

// maxLine bounds one record. The store writes nothing near it, but a file
// from an older build can hold longer lines; each one is counted as corrupt
// and skipped, and that proxy is checked again.
const maxLine = 1024 * 1024

// Load reads the results already in the file at path. A missing file is not an
// error: there is simply nothing to resume from. A file in the other format is:
// read as the wrong one, every record of it came out unreadable, so every
// proxy was checked again and appended in a second format.
func Load(path, format string) (*Set, error) {
	s := &Set{seen: make(map[uint64]struct{})}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read only the whole records. A run killed mid-write leaves a torn last
	// line that the store cuts off before appending; taking it as done would
	// skip a proxy the file no longer holds, however much of it parses.
	whole, size, err := store.Intact(f)
	if err != nil {
		return nil, err
	}
	if whole < size {
		s.corrupt++
	}
	r := io.NewSectionReader(f, 0, whole)
	want := "jsonl" // what the store writes for any format but csv
	if format == "csv" {
		want = "csv"
	}
	if found := sniff(r); found != "" && found != want {
		return nil, fmt.Errorf("%s holds %s records, not %s: resume it with -format %s", path, found, want, found)
	}
	if format == "csv" {
		err = s.loadCSV(r)
	} else {
		err = s.loadJSONL(r)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// sniff tells a results file's format from how it starts: the store opens a
// CSV file with its header row, and every JSONL record with a brace. A start
// it does not know gives "", and the file is read as asked.
func sniff(r io.ReaderAt) string {
	var head [len("host,")]byte
	n, _ := r.ReadAt(head[:], 0) // a failed read surfaces when the records are read
	switch {
	case n > 0 && head[0] == '{':
		return "jsonl"
	case string(head[:n]) == "host,":
		return "csv"
	}
	return ""
}

// loadJSONL reads one record per line. A line that does not parse is counted
// and skipped, and that proxy is simply checked again. So is a line longer
// than maxLine: it used to fail the whole load, and every later -resume of
// that file with it.
func (s *Set) loadJSONL(r io.Reader) error {
	br := bufio.NewReaderSize(r, maxLine)
	for {
		line, long, err := br.ReadLine()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if long {
			s.corrupt++
			for long && err == nil {
				_, long, err = br.ReadLine()
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			continue
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var rec struct {
			Host string `json:"host"`
			Port uint16 `json:"port"`
			Link string `json:"link"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.Host == "" || rec.Port == 0 {
			s.corrupt++
			continue
		}
		if !s.add(rec.Host, rec.Port, rec.Link) {
			s.corrupt++
		}
	}
}

// add remembers one record: a share link by what it connects with, a classic
// proxy by its address. A link that no longer parses is not remembered, and
// is checked again.
func (s *Set) add(host string, port uint16, raw string) bool {
	if raw == "" {
		s.seen[key(host, port)] = struct{}{}
		return true
	}
	l, err := link.Parse(raw)
	if err != nil {
		return false
	}
	s.seen[linkKey(l)] = struct{}{}
	return true
}

// loadCSV reads the table written by store.NewCSV. Reading stops at the first
// malformed record rather than guessing past it; everything after it is
// checked again.
func (s *Set) loadCSV(r io.Reader) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.ReuseRecord = true

	first := true
	linkCol := -1 // files from before share links have no such column
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			s.corrupt++
			return nil
		}
		if first {
			first = false
			if len(rec) > 0 && rec[0] == "host" { // header
				linkCol = slices.Index(rec, "link")
				continue
			}
		}
		if len(rec) < 2 {
			s.corrupt++
			return nil
		}
		port, err := strconv.ParseUint(rec[1], 10, 16)
		if err != nil || port == 0 || rec[0] == "" {
			s.corrupt++
			return nil
		}
		var raw string
		if linkCol >= 0 && linkCol < len(rec) {
			raw = rec[linkCol]
		}
		if !s.add(rec[0], uint16(port), raw) {
			s.corrupt++
		}
	}
}

// Len is how many proxies the previous run recorded. A nil set is the "not
// resuming" case, so every reader below tolerates it.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.seen)
}

// Corrupt is how many records could not be read back, usually the single
// partial line left by a kill.
func (s *Set) Corrupt() int {
	if s == nil {
		return 0
	}
	return s.corrupt
}

// Skipped is how many proxies Filter held back so far.
func (s *Set) Skipped() int64 {
	if s == nil {
		return 0
	}
	return s.skipped.Load()
}

// Has reports whether the previous run already recorded this proxy.
func (s *Set) Has(p probe.Proxy) bool {
	if s == nil {
		return false
	}
	k := key(p.Host, p.Port)
	if p.Link != nil {
		k = linkKey(p.Link)
	}
	_, ok := s.seen[k]
	return ok
}

// Filter drops the proxies already recorded. An empty set returns the input
// channel untouched, so a fresh run pays nothing for the feature.
func (s *Set) Filter(ctx context.Context, in <-chan probe.Proxy) <-chan probe.Proxy {
	if s == nil || len(s.seen) == 0 {
		return in
	}
	out := make(chan probe.Proxy, cap(in))
	go func() {
		defer close(out)
		for p := range in {
			if s.Has(p) {
				s.skipped.Add(1)
				continue
			}
			select {
			case out <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// linkKey hashes one share link by what it connects with, so the same link
// under another name counts as done. What it hashes starts with a zero byte,
// which no host does, so a link and a proxy never hash the same text.
func linkKey(l *link.Link) uint64 {
	h := fnv.New64a()
	io.WriteString(h, "\x00link\x00")
	io.WriteString(h, l.Key())
	return h.Sum64()
}

// key hashes one proxy. Host case is normalised, because a hostname list may
// spell the same host two ways across runs.
func key(host string, port uint16) uint64 {
	h := fnv.New64a()
	io.WriteString(h, strings.ToLower(host))
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], port)
	h.Write(b[:])
	return h.Sum64()
}
