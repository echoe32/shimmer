package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shimmer/internal/probe"
	"shimmer/internal/store"
)

func tableCount(t *testing.T, path, table string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// -alive-only shapes the results file only: the dead still reach the
// database, in their own table.
func TestDatabaseKeepsEveryResult(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "proxies.txt")
	results := filepath.Join(dir, "results.jsonl")
	dbPath := filepath.Join(dir, "shimmer.db")
	if err := os.WriteFile(input, []byte("127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withArgs(t, "-quiet", "-timeout", "2s", "-i", input, "-o", results, "-alive-only", "-db", dbPath)

	if err := run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if data, err := os.ReadFile(results); err != nil || len(data) != 0 {
		t.Errorf("results file holds %q (%v), want nothing: the only proxy is dead", data, err)
	}
	if n := tableCount(t, dbPath, "dead"); n != 1 {
		t.Errorf("dead holds %d rows, want 1", n)
	}
	if n := tableCount(t, dbPath, "live"); n != 0 {
		t.Errorf("live holds %d rows, want 0", n)
	}
}

// With only a database asked for, results do not also flood stdout.
func TestDatabaseAloneWritesNoResultsFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "shimmer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"output":"from-file.jsonl"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-db", "shimmer.db"}, ""},
		{[]string{"-db", "shimmer.db", "-o", "-"}, "-"},
		{[]string{"-db", "shimmer.db", "-config", cfgPath}, "from-file.jsonl"},
		{[]string{}, "-"},
	} {
		withArgs(t, c.args...)
		opt, err := settings()
		if err != nil {
			t.Fatalf("settings(%v): %v", c.args, err)
		}
		if opt.cfg.Output != c.want {
			t.Errorf("settings(%v): output %q, want %q", c.args, opt.cfg.Output, c.want)
		}
	}
}

// Opening the results file empties it, so a results path that names the
// database would destroy what earlier runs saved there.
func TestOutputThatIsTheDatabaseIsRefused(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "proxies.txt")
	dbPath := filepath.Join(dir, "shimmer.db")
	if err := os.WriteFile(input, []byte("127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	earlier, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	alive := probe.Result{Proxy: probe.Proxy{Host: "192.0.2.1", Port: 1080}, Protocol: probe.SOCKS5, Alive: true, CheckedAt: time.Now()}
	if err := earlier.Write(context.Background(), alive); err != nil {
		t.Fatal(err)
	}
	if err := earlier.Close(); err != nil {
		t.Fatal(err)
	}

	fresh := filepath.Join(dir, "new.db")
	for name, args := range map[string][]string{
		"same path":       {"-o", dbPath, "-db", dbPath},
		"spelled apart":   {"-o", filepath.Join(dir, "sub", "..", "shimmer.db"), "-db", dbPath},
		"neither there":   {"-o", fresh, "-db", fresh},
		"resumed onto it": {"-resume", "-format", "csv", "-o", dbPath, "-db", dbPath},
	} {
		t.Run(name, func(t *testing.T) {
			withArgs(t, append([]string{"-quiet", "-i", input}, args...)...)
			if err := run(context.Background()); err == nil {
				t.Fatal("run accepted a results file that is the database")
			}
			if n := tableCount(t, dbPath, "live"); n != 1 {
				t.Errorf("live holds %d rows, want the 1 an earlier run saved", n)
			}
		})
	}
}

// The check used to run only once the database was open. SQLite takes an empty
// file for a database with nothing in it yet, so an empty results file named
// as both was refused only after it had been made into one.
func TestOutputThatIsTheDatabaseIsRefusedBeforeItIsOpened(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "proxies.txt")
	results := filepath.Join(dir, "results.jsonl")
	if err := os.WriteFile(input, []byte("127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(results, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withArgs(t, "-quiet", "-i", input, "-o", results, "-db", filepath.Join(dir, ".", "results.jsonl"))

	err := run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "would destroy it") {
		t.Errorf("err = %v, want the output refused", err)
	}
	if data, err := os.ReadFile(results); err != nil || len(data) != 0 {
		t.Errorf("results file holds %d bytes (%v), want it left empty", len(data), err)
	}
}

func TestRecordSendsEveryResultToDatabase(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	results := make(chan probe.Result, 3)
	results <- probe.Result{Alive: true}
	results <- probe.Result{}
	results <- probe.Result{}
	close(results)

	var out, db countingStore
	written, saved, err := record(ctx, stop, results, &out, &db, true)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if written != 1 || out.n != 1 {
		t.Errorf("results file got %d (reported %d), want only the live one", out.n, written)
	}
	if saved != 3 || db.n != 3 {
		t.Errorf("database got %d (reported %d), want all 3", db.n, saved)
	}
}

func TestRecordReportsDatabaseFailure(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	results := make(chan probe.Result, 1)
	results <- probe.Result{Alive: true}
	close(results)

	if _, _, err := record(ctx, stop, results, nil, failingStore{}, false); !errors.Is(err, errDiskFull) {
		t.Errorf("err = %v, want the database's write failure", err)
	}
}

type countingStore struct{ n int }

func (s *countingStore) Write(context.Context, probe.Result) error { s.n++; return nil }

func (s *countingStore) Close() error { return nil }

// A list can mix classic proxies and share links. Each goes to its own
// tables, and the results file names the link it checked.
func TestMixedListReachesEveryTable(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "list.txt")
	results := filepath.Join(dir, "results.jsonl")
	dbPath := filepath.Join(dir, "shimmer.db")
	const link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:1?security=none#dead-link"
	if err := os.WriteFile(input, []byte("127.0.0.1:1\n"+link+"\nssr://unsupported\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withArgs(t, "-quiet", "-timeout", "2s", "-i", input, "-o", results, "-db", dbPath)
	if err := run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if n := tableCount(t, dbPath, "dead"); n != 1 {
		t.Errorf("dead holds %d rows, want 1", n)
	}
	if n := tableCount(t, dbPath, "dead_links"); n != 1 {
		t.Errorf("dead_links holds %d rows, want 1", n)
	}
	data, err := os.ReadFile(results)
	if err != nil {
		t.Fatal(err)
	}
	var sawLink bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec struct {
			Protocol string `json:"protocol"`
			Link     string `json:"link"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("%v in %q", err, line)
		}
		if rec.Link != "" {
			sawLink = rec.Link == link && rec.Protocol == "vless"
		}
	}
	if !sawLink {
		t.Errorf("results hold no record for the link:\n%s", data)
	}
}
