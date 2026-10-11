package store

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendKeepsEarlierRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	first := `{"host":"1.1.1.1","port":80,"alive":true}` + "\n"
	if err := os.WriteFile(path, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "jsonl", Append)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	writeAll(t, s, sample())

	lines := nonEmptyLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3: the earlier record was lost", len(lines))
	}
	if !strings.Contains(lines[0], "1.1.1.1") {
		t.Errorf("first line is %q, want the record already there", lines[0])
	}
	if !strings.Contains(lines[1], "1.2.3.4") {
		t.Errorf("second line is %q, want the first appended record", lines[1])
	}
}

func TestAppendDropsThePartialLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	body := `{"host":"1.1.1.1","port":80}` + "\n" + `{"host":"2.2.2.2","po` // killed mid-write
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "jsonl", Append)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	writeAll(t, s, sample()[:1])

	lines := nonEmptyLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2", len(lines))
	}
	for _, l := range lines {
		if strings.Contains(l, `"po"`) || strings.Contains(l, "2.2.2.2") {
			t.Fatalf("the partial line survived: %q", l)
		}
		if !strings.HasPrefix(l, "{") || !strings.HasSuffix(l, "}") {
			t.Fatalf("line is not a whole record: %q", l)
		}
	}
}

func TestAppendToFileWithNoNewlineAtAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	if err := os.WriteFile(path, []byte(`{"host":"1.1.1.1","po`), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, "jsonl", Append)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	writeAll(t, s, sample()[:1])

	lines := nonEmptyLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("%d lines, want only the appended one", len(lines))
	}
	if !strings.Contains(lines[0], "1.2.3.4") {
		t.Errorf("line is %q, want the appended record", lines[0])
	}
}

func TestAppendToMissingFileJustCreatesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.jsonl")
	s, err := Open(path, "jsonl", Append)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	writeAll(t, s, sample())

	if n := len(nonEmptyLines(t, path)); n != 2 {
		t.Errorf("%d lines, want 2", n)
	}
}

func TestCSVAppendWritesOneHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")

	s, err := Open(path, "csv", Truncate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	writeAll(t, s, sample())

	s, err = Open(path, "csv", Append)
	if err != nil {
		t.Fatalf("Open append: %v", err)
	}
	writeAll(t, s, sample())

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(rows) != 5 { // header + two runs of two
		t.Fatalf("%d rows, want 5", len(rows))
	}
	for i, row := range rows[1:] {
		if row[0] == "host" {
			t.Errorf("row %d is a second header", i+1)
		}
	}
}

func TestCSVAppendToMissingFileWritesTheHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.csv")
	s, err := Open(path, "csv", Append)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	writeAll(t, s, sample()[:1])

	lines := nonEmptyLines(t, path)
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "host,port") {
		t.Fatalf("file is %q, want a header and one row", lines)
	}
}

func TestAppendToStdoutIsRefused(t *testing.T) {
	if _, err := Open("-", "jsonl", Append); err == nil {
		t.Error("appending to stdout was accepted; it cannot work")
	}
}

func nonEmptyLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}
