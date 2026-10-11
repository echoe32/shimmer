package resume

import (
	"path/filepath"
	"testing"
	"time"

	"shimmer/internal/link"
	"shimmer/internal/probe"
	"shimmer/internal/store"
)

func linkProxy(t *testing.T, raw string) probe.Proxy {
	t.Helper()
	l, err := link.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return probe.Proxy{Host: l.Host, Port: l.Port, Link: l}
}

// Links are done by what they connect with. Many share a server, so their
// address says nothing, and a link renamed in a later list is still done.
func TestLinksResumeByConfig(t *testing.T) {
	const base = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.7:443?type=ws&security=none&path="
	done := linkProxy(t, base+"/a#one")
	for _, format := range []string{"jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "r."+format)
			writeResults(t, path, format, store.Truncate,
				probe.Result{Proxy: done, Protocol: probe.VLESS, CheckedAt: time.Now()},
				probe.Result{Proxy: probe.Proxy{Host: "203.0.113.7", Port: 443}, Protocol: probe.HTTPS, Alive: true, CheckedAt: time.Now()},
			)
			s, err := Load(path, format)
			if err != nil {
				t.Fatal(err)
			}
			if s.Len() != 2 || s.Corrupt() != 0 {
				t.Errorf("Len %d, Corrupt %d; want 2 and 0", s.Len(), s.Corrupt())
			}
			if !s.Has(linkProxy(t, base+"/a#renamed")) {
				t.Error("the same link under another name is not done")
			}
			if s.Has(linkProxy(t, base+"/b#one")) {
				t.Error("another link on the same server counts as done")
			}
			if !s.Has(probe.Proxy{Host: "203.0.113.7", Port: 443}) {
				t.Error("the classic proxy on that address is not done")
			}
		})
	}
}

// A CSV file from before links has no link column; its rows are still read.
func TestOldCSVWithoutLinkColumn(t *testing.T) {
	path := write(t, "r.csv", "host,port,protocol,alive,connect_ms,total_ms,exit_ip,country,asn,error,checked_at\n1.2.3.4,8080,http,true,1,2,,,0,,2026-09-24T10:00:00Z\n")
	s, err := Load(path, "csv")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Has(probe.Proxy{Host: "1.2.3.4", Port: 8080}) || s.Corrupt() != 0 {
		t.Errorf("old CSV: has %v, corrupt %d", s.Has(probe.Proxy{Host: "1.2.3.4", Port: 8080}), s.Corrupt())
	}
}

// A record whose link no longer parses is counted unreadable, and checked
// again, rather than taken as its address.
func TestUnreadableLinkRecord(t *testing.T) {
	path := write(t, "r.jsonl", `{"host":"1.2.3.4","port":443,"link":"vless://broken"}`+"\n")
	s, err := Load(path, "jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if s.Corrupt() != 1 || s.Has(probe.Proxy{Host: "1.2.3.4", Port: 443}) {
		t.Errorf("corrupt %d, has %v; want 1 and false", s.Corrupt(), s.Has(probe.Proxy{Host: "1.2.3.4", Port: 443}))
	}
}
