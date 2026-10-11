package store

import (
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shimmer/internal/link"
	"shimmer/internal/probe"
)

const vlessLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.7:443?type=ws&path=/p&security=tls&sni=a.example.com#first%0Aname"

func linkResult(t *testing.T, raw string, alive bool) probe.Result {
	t.Helper()
	l, err := link.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := probe.Result{
		Proxy:      probe.Proxy{Host: l.Host, Port: l.Port, Link: l},
		Protocol:   probe.Protocol(l.Protocol),
		Alive:      alive,
		ConnectRTT: 12 * time.Millisecond,
		CheckedAt:  time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC),
	}
	if alive {
		r.TotalRTT = 80 * time.Millisecond
		r.ExitIP = netip.MustParseAddr("198.51.100.4")
		r.Country = "DE"
	} else {
		r.Err = errTest
	}
	return r
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTest = testErr("reality: handshake failed")

func TestJSONLRecordsLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	writeAll(t, s, []probe.Result{linkResult(t, vlessLink, true)})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("%v in %s", err, data)
	}
	want := map[string]any{
		"host": "203.0.113.7", "protocol": "vless", "transport": "ws", "security": "tls",
		"name": "first; name", "link": vlessLink, "exit_ip": "198.51.100.4",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s = %v, want %v", k, rec[k], v)
		}
	}
	// The link reads as itself in the file too, not only once decoded: its
	// '&' is not escaped as &.
	if !strings.Contains(string(data), `"link":"`+vlessLink+`"`) {
		t.Errorf("link not written as is: %s", data)
	}
}

// A classic proxy's record carries none of the link fields.
func TestJSONLClassicRecordHasNoLinkFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	writeAll(t, s, sample()[:1])
	data, _ := os.ReadFile(path)
	var rec map[string]any
	json.Unmarshal(data, &rec)
	for _, k := range []string{"transport", "security", "name", "link"} {
		if _, ok := rec[k]; ok {
			t.Errorf("classic record has %q: %s", k, data)
		}
	}
}

func TestCSVRecordsLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.csv")
	s, err := NewCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	writeAll(t, s, []probe.Result{linkResult(t, vlessLink, false)})
	f, _ := os.Open(path)
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows", len(rows))
	}
	row := map[string]string{}
	for i, col := range rows[0] {
		row[col] = rows[1][i]
	}
	if row["protocol"] != "vless" || row["link"] != vlessLink || row["error"] != string(errTest) || row["transport"] != "ws" {
		t.Errorf("row %v", row)
	}
}

// Links have tables of their own, keyed by what they connect with: the same
// link under another name replaces its row, and moves between live and dead.
func TestSQLiteLinkTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shimmer.db")
	renamed := vlessLink[:len(vlessLink)-len("first%0Aname")] + "second"
	other := "trojan://pw@203.0.113.7:443#same-server"

	s := openSQLite(t, path)
	writeAll(t, s, []probe.Result{
		linkResult(t, vlessLink, true),
		linkResult(t, other, false),
	})
	db := query(t, path)
	if count(t, db, "live_links") != 1 || count(t, db, "dead_links") != 1 {
		t.Fatalf("live_links %d, dead_links %d; want 1 and 1", count(t, db, "live_links"), count(t, db, "dead_links"))
	}
	if count(t, db, "live")+count(t, db, "dead") != 0 {
		t.Error("a link went into the proxy tables")
	}
	var id, exitIP, country, name string
	if err := db.QueryRow("SELECT id, exit_ip, country, name FROM live_links").Scan(&id, &exitIP, &country, &name); err != nil {
		t.Fatal(err)
	}
	if exitIP != "198.51.100.4" || country != "DE" || name != "first; name" || len(id) != 32 {
		t.Errorf("row id %q exit %q country %q name %q", id, exitIP, country, name)
	}

	// The same link, renamed and now dead, moves; the other link stays.
	s = openSQLite(t, path)
	writeAll(t, s, []probe.Result{linkResult(t, renamed, false)})
	if count(t, db, "live_links") != 0 || count(t, db, "dead_links") != 2 {
		t.Errorf("live_links %d, dead_links %d; want 0 and 2", count(t, db, "live_links"), count(t, db, "dead_links"))
	}

	// Left out, it is gone from both.
	left := linkResult(t, vlessLink, false)
	left.LeftOut = true
	s = openSQLite(t, path)
	writeAll(t, s, []probe.Result{left})
	if count(t, db, "live_links") != 0 || count(t, db, "dead_links") != 1 {
		t.Errorf("live_links %d, dead_links %d; want 0 and 1", count(t, db, "live_links"), count(t, db, "dead_links"))
	}
}
