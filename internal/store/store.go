// Package store persists results. A single goroutine owns the writer, so no
// locking is needed.
package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"shimmer/internal/probe"
)

// Store writes results as they arrive. A result marked LeftOut is no record:
// the file stores ignore it, and the database removes its proxy.
type Store interface {
	Write(ctx context.Context, r probe.Result) error
	Close() error
}

// flushEvery bounds how much finished work a crash can lose. Results arrive
// over seconds, not microseconds, so flushing often costs nothing real.
const flushEvery = 256

// record is the on-disk shape of a result: flat, with durations in
// milliseconds and the error reduced to its message. The link fields are
// empty for a classic proxy, and left out of its JSON.
type record struct {
	Host      string    `json:"host"`
	Port      uint16    `json:"port"`
	Protocol  string    `json:"protocol"`
	Transport string    `json:"transport,omitempty"`
	Security  string    `json:"security,omitempty"`
	Alive     bool      `json:"alive"`
	ConnectMS float64   `json:"connect_ms"`
	TotalMS   float64   `json:"total_ms"`
	ExitIP    string    `json:"exit_ip,omitempty"`
	Country   string    `json:"country,omitempty"`
	ASN       uint      `json:"asn,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	Name      string    `json:"name,omitempty"`
	Link      string    `json:"link,omitempty"`
}

func newRecord(r probe.Result) record {
	rec := record{
		Host:      r.Proxy.Host,
		Port:      r.Proxy.Port,
		Protocol:  string(r.Protocol),
		Alive:     r.Alive,
		ConnectMS: ms(r.ConnectRTT),
		TotalMS:   ms(r.TotalRTT),
		Country:   r.Country,
		ASN:       r.ASN,
		CheckedAt: r.CheckedAt,
	}
	if l := r.Proxy.Link; l != nil {
		rec.Transport = l.Transport
		rec.Security = l.Security
		rec.Name = oneLine(l.Name)
		rec.Link = l.Raw
	}
	if r.ExitIP.IsValid() {
		rec.ExitIP = r.ExitIP.String()
	}
	if r.Err != nil {
		rec.Error = oneLine(r.Err.Error())
	}
	if rec.Protocol == "" {
		rec.Protocol = string(probe.Unknown)
	}
	return rec
}

// oneLine keeps a field on one line, in both formats: errors.Join separates
// the ladder's attempts with newlines, a link's name can hold an escaped one,
// and a newline inside a CSV field splits a row across lines, which trimming a
// torn tail cannot survive.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", "; ")
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// Mode says what an existing file at the output path means.
type Mode int

const (
	// Truncate throws away whatever was there. This is the normal mode.
	Truncate Mode = iota
	// Append continues an earlier run's file, keeping its records.
	Append
)

// Open builds the store for a format: "csv" for the flat table, anything else
// for one JSON object per line.
func Open(path, format string, m Mode) (Store, error) {
	if format == "csv" {
		return newCSV(path, m)
	}
	return newJSONL(path, m)
}

// openSink opens path for writing. The path "-" (or empty) writes to stdout,
// which is then left open on Close. In Append mode the file is created if it
// is missing, and the returned size is what it already held.
func openSink(path string, m Mode) (w io.Writer, c io.Closer, size int64, err error) {
	if path == "-" || path == "" {
		if m == Append {
			return nil, nil, 0, errors.New("cannot append to stdout: give -o a file")
		}
		return os.Stdout, nil, 0, nil
	}
	if m != Append {
		f, err := os.Create(path)
		if err != nil {
			return nil, nil, 0, err
		}
		return f, f, 0, nil
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, nil, 0, err
	}
	// A run killed mid-write leaves a partial last line. Appending after it
	// would glue two records together, so drop it: at most one record is lost,
	// and that proxy is checked again.
	size, err = trimPartialLine(f)
	if err != nil {
		f.Close()
		return nil, nil, 0, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, nil, 0, err
	}
	return f, f, size, nil
}

// trimPartialLine cuts the file back to its last complete line and reports the
// size that leaves. A file that is empty, or that already ends in a newline,
// is left alone.
func trimPartialLine(f *os.File) (int64, error) {
	whole, size, err := Intact(f)
	if err != nil {
		return 0, err
	}
	if whole < size {
		if err := f.Truncate(whole); err != nil {
			return 0, err
		}
	}
	return whole, nil
}

// Intact reports how much of a results file holds whole records (everything
// up to and including its last newline) and how big the file is. What lies
// past that point is the torn tail of a killed run: Open in Append mode cuts
// it off, and resume must not count it as done, so both ask here.
func Intact(f *os.File) (whole, size int64, err error) {
	info, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	size = info.Size()

	const window = 64 * 1024
	buf := make([]byte, window)
	for end := size; end > 0; {
		start := max(end-window, 0)
		n, err := f.ReadAt(buf[:end-start], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			return start + int64(i) + 1, size, nil
		}
		end = start
	}
	return 0, size, nil // no newline anywhere: the whole file is one partial line
}

// jsonlStore writes one JSON object per line.
type jsonlStore struct {
	buf    *bufio.Writer
	closer io.Closer
	enc    *json.Encoder
	n      int
	closed bool
}

// NewJSONL writes one JSON object per line to path, replacing what was there.
func NewJSONL(path string) (Store, error) { return newJSONL(path, Truncate) }

func newJSONL(path string, m Mode) (Store, error) {
	w, closer, _, err := openSink(path, m)
	if err != nil {
		return nil, err
	}
	buf := bufio.NewWriterSize(w, 64*1024)
	enc := json.NewEncoder(buf) // Encode already terminates each object with \n
	// A link's query joins its parameters with '&'. Escaped as &, the
	// link read straight from the file was no link a client could import.
	enc.SetEscapeHTML(false)
	return &jsonlStore{buf: buf, closer: closer, enc: enc}, nil
}

func (s *jsonlStore) Write(ctx context.Context, r probe.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.LeftOut {
		return nil
	}
	if err := s.enc.Encode(newRecord(r)); err != nil {
		return err
	}
	s.n++
	if s.n%flushEvery == 0 {
		return s.buf.Flush()
	}
	return nil
}

func (s *jsonlStore) Close() error {
	if s.closed { // Close is deferred and also called explicitly on a clean run
		return nil
	}
	s.closed = true
	if err := s.buf.Flush(); err != nil {
		if s.closer != nil {
			s.closer.Close()
		}
		return err
	}
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

// csvStore writes a flat table with a header row.
type csvStore struct {
	buf    *bufio.Writer
	w      *csv.Writer
	closer io.Closer
	n      int
	closed bool
}

// csvHeader keeps the classic columns first and in their old order, so a
// file started by an older build can still be resumed and appended to.
var csvHeader = []string{
	"host", "port", "protocol", "alive", "connect_ms", "total_ms",
	"exit_ip", "country", "asn", "error", "checked_at",
	"transport", "security", "name", "link",
}

// NewCSV writes a flat table to path, replacing what was there.
func NewCSV(path string) (Store, error) { return newCSV(path, Truncate) }

func newCSV(path string, m Mode) (Store, error) {
	sink, closer, size, err := openSink(path, m)
	if err != nil {
		return nil, err
	}
	buf := bufio.NewWriterSize(sink, 64*1024)
	w := csv.NewWriter(buf)
	// An appended file already carries its header; a new or empty one needs it.
	if size == 0 {
		if err := w.Write(csvHeader); err != nil {
			if closer != nil {
				closer.Close()
			}
			return nil, err
		}
	}
	return &csvStore{buf: buf, w: w, closer: closer}, nil
}

func (s *csvStore) Write(ctx context.Context, r probe.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.LeftOut {
		return nil
	}
	rec := newRecord(r)
	row := []string{
		rec.Host,
		strconv.Itoa(int(rec.Port)),
		rec.Protocol,
		strconv.FormatBool(rec.Alive),
		strconv.FormatFloat(rec.ConnectMS, 'f', 3, 64),
		strconv.FormatFloat(rec.TotalMS, 'f', 3, 64),
		rec.ExitIP,
		rec.Country,
		strconv.FormatUint(uint64(rec.ASN), 10),
		rec.Error,
		rec.CheckedAt.Format(time.RFC3339),
		rec.Transport,
		rec.Security,
		rec.Name,
		rec.Link,
	}
	if err := s.w.Write(row); err != nil {
		return err
	}
	s.n++
	if s.n%flushEvery == 0 {
		s.w.Flush()
		return s.w.Error()
	}
	return nil
}

func (s *csvStore) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.w.Flush()
	err := s.w.Error()
	if ferr := s.buf.Flush(); err == nil {
		err = ferr
	}
	if s.closer != nil {
		if cerr := s.closer.Close(); err == nil {
			err = cerr
		}
	}
	return err
}
