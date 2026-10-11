package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shimmer/internal/probe"
)

func openSQLite(t *testing.T, path string) Store {
	t.Helper()
	s, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	return s
}

// query opens the database the way any other reader would.
func query(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestSQLiteSplitsLiveAndDead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shimmer.db")
	writeAll(t, openSQLite(t, path), sample())
	db := query(t, path)

	if n := count(t, db, "live"); n != 1 {
		t.Errorf("live holds %d rows, want 1", n)
	}
	if n := count(t, db, "dead"); n != 1 {
		t.Errorf("dead holds %d rows, want 1", n)
	}

	var (
		protocol, exitIP, country, checkedAt string
		connectMS, totalMS                   float64
		asn                                  int64
	)
	err := db.QueryRow(`SELECT protocol, connect_ms, total_ms, exit_ip, country, asn, checked_at
		FROM live WHERE host = '1.2.3.4' AND port = 1080`).
		Scan(&protocol, &connectMS, &totalMS, &exitIP, &country, &asn, &checkedAt)
	if err != nil {
		t.Fatalf("read live row: %v", err)
	}
	if protocol != "socks5" || connectMS != 12 || totalMS != 140 {
		t.Errorf("live row: protocol %q, connect %v, total %v", protocol, connectMS, totalMS)
	}
	if exitIP != "5.6.7.8" || country != "DE" || asn != 64500 {
		t.Errorf("live geo: exit %q, country %q, asn %d", exitIP, country, asn)
	}
	if at, err := time.Parse(time.RFC3339Nano, checkedAt); err != nil || !at.Equal(sample()[0].CheckedAt) {
		t.Errorf("checked_at %q does not round-trip: %v", checkedAt, err)
	}

	var reason string
	err = db.QueryRow(`SELECT error FROM dead WHERE host = '9.9.9.9' AND port = 3128`).Scan(&reason)
	if err != nil {
		t.Fatalf("read dead row: %v", err)
	}
	if !strings.Contains(reason, "connection refused") {
		t.Errorf("dead error = %q", reason)
	}
}

// What a check did not find is NULL, not an empty string or ASN 0.
func TestSQLiteUnknownFieldsAreNull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shimmer.db")
	bare := probe.Result{
		Proxy:     probe.Proxy{Host: "1.2.3.4", Port: 8080},
		Protocol:  probe.HTTP,
		Alive:     true,
		CheckedAt: time.Now(),
	}
	writeAll(t, openSQLite(t, path), []probe.Result{bare})

	var exitIP, country sql.NullString
	var asn sql.NullInt64
	err := query(t, path).QueryRow(`SELECT exit_ip, country, asn FROM live`).Scan(&exitIP, &country, &asn)
	if err != nil {
		t.Fatal(err)
	}
	if exitIP.Valid || country.Valid || asn.Valid {
		t.Errorf("unknown fields stored as values: exit %v, country %v, asn %v", exitIP, country, asn)
	}
}

// Each run adds to the database, and a proxy's latest check decides which
// table it is in. Hosts match whatever their case.
func TestSQLiteMovesProxyBetweenTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shimmer.db")
	alive := probe.Result{
		Proxy:     probe.Proxy{Host: "proxy.example", Port: 1080},
		Protocol:  probe.SOCKS5,
		Alive:     true,
		CheckedAt: time.Unix(1700000000, 0),
	}
	dead := probe.Result{
		Proxy:     probe.Proxy{Host: "PROXY.example", Port: 1080},
		Err:       errors.New("dial tcp: i/o timeout"),
		CheckedAt: time.Unix(1700000100, 0),
	}
	leftOut := probe.Result{
		Proxy:     probe.Proxy{Host: "Proxy.Example", Port: 1080},
		Protocol:  probe.SOCKS4,
		LeftOut:   true,
		CheckedAt: time.Unix(1700000200, 0),
	}

	for i, step := range []struct {
		r          probe.Result
		live, dead int
	}{
		{alive, 1, 0},
		{dead, 0, 1},
		{alive, 1, 0},
		{alive, 1, 0}, // checked again: updated, not duplicated
		{leftOut, 0, 0},
		{dead, 0, 1},
		{leftOut, 0, 0},
		{leftOut, 0, 0}, // nothing left to remove
	} {
		writeAll(t, openSQLite(t, path), []probe.Result{step.r}) // a separate run each time
		db := query(t, path)
		if l, d := count(t, db, "live"), count(t, db, "dead"); l != step.live || d != step.dead {
			t.Fatalf("after run %d: live %d, dead %d; want %d and %d", i+1, l, d, step.live, step.dead)
		}
		db.Close()
	}
}

// A run cut short must still leave the finished part of its batch behind.
func TestSQLiteCloseCommitsAfterInterrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shimmer.db")
	s := openSQLite(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	for i := range 3 { // far below flushEvery
		r := sample()[0]
		r.Proxy.Port = uint16(1000 + i)
		if err := s.Write(ctx, r); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	cancel()
	if err := s.Write(ctx, sample()[1]); !errors.Is(err, context.Canceled) {
		t.Errorf("Write after cancel returned %v, want context.Canceled", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := count(t, query(t, path), "live"); n != 3 {
		t.Errorf("live holds %d rows after the interrupt, want 3", n)
	}
}

func TestSQLiteWritesAcrossBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shimmer.db")
	const n = 2*flushEvery + 5
	results := make([]probe.Result, n)
	for i := range results {
		results[i] = sample()[i%2]
		results[i].Proxy.Host = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}
	writeAll(t, openSQLite(t, path), results)

	db := query(t, path)
	if total := count(t, db, "live") + count(t, db, "dead"); total != n {
		t.Errorf("database holds %d rows, want %d", total, n)
	}
}

// A path that holds something else is refused, and left as it was.
func TestSQLiteRefusesFileThatIsNotADatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.jsonl")
	const body = `{"host":"1.2.3.4","port":80,"alive":true}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if s, err := NewSQLite(path); err == nil {
		s.Close()
		t.Fatal("NewSQLite opened a JSONL file as a database")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != body {
		t.Errorf("file is now %q, want it untouched", data)
	}
}
