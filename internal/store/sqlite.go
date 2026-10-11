package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"shimmer/internal/probe"
)

// The database keeps the latest result for every proxy it has ever seen,
// split by outcome. A proxy is in exactly one table: each check puts it in
// the table for its outcome and removes it from the other one. A proxy left
// out by -skip is removed from both.
//
// Share links have tables of their own, live_links and dead_links. Many links
// share a server (a CDN address fronts hundreds), so a link is keyed by what
// it connects with, not by host and port: id is link.Link.ID, which two links
// differing only in their names share.
const schema = `
CREATE TABLE IF NOT EXISTS live (
	host       TEXT    NOT NULL COLLATE NOCASE,
	port       INTEGER NOT NULL,
	protocol   TEXT    NOT NULL,
	connect_ms REAL    NOT NULL,
	total_ms   REAL    NOT NULL,
	exit_ip    TEXT,
	country    TEXT,
	asn        INTEGER,
	checked_at TEXT    NOT NULL,
	PRIMARY KEY (host, port)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dead (
	host       TEXT    NOT NULL COLLATE NOCASE,
	port       INTEGER NOT NULL,
	connect_ms REAL    NOT NULL,
	error      TEXT,
	checked_at TEXT    NOT NULL,
	PRIMARY KEY (host, port)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS live_links (
	id         TEXT    NOT NULL PRIMARY KEY,
	protocol   TEXT    NOT NULL,
	transport  TEXT    NOT NULL,
	security   TEXT    NOT NULL,
	host       TEXT    NOT NULL,
	port       INTEGER NOT NULL,
	name       TEXT,
	link       TEXT    NOT NULL,
	connect_ms REAL    NOT NULL,
	total_ms   REAL    NOT NULL,
	exit_ip    TEXT,
	country    TEXT,
	asn        INTEGER,
	checked_at TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS dead_links (
	id         TEXT    NOT NULL PRIMARY KEY,
	protocol   TEXT    NOT NULL,
	transport  TEXT    NOT NULL,
	security   TEXT    NOT NULL,
	host       TEXT    NOT NULL,
	port       INTEGER NOT NULL,
	name       TEXT,
	link       TEXT    NOT NULL,
	connect_ms REAL    NOT NULL,
	error      TEXT,
	checked_at TEXT    NOT NULL
);`

const (
	putLiveSQL = `INSERT OR REPLACE INTO live
		(host, port, protocol, connect_ms, total_ms, exit_ip, country, asn, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	putDeadSQL = `INSERT OR REPLACE INTO dead
		(host, port, connect_ms, error, checked_at)
		VALUES (?, ?, ?, ?, ?)`
	delLiveSQL = `DELETE FROM live WHERE host = ? AND port = ?`
	delDeadSQL = `DELETE FROM dead WHERE host = ? AND port = ?`

	putLiveLinkSQL = `INSERT OR REPLACE INTO live_links
		(id, protocol, transport, security, host, port, name, link, connect_ms, total_ms, exit_ip, country, asn, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	putDeadLinkSQL = `INSERT OR REPLACE INTO dead_links
		(id, protocol, transport, security, host, port, name, link, connect_ms, error, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	delLiveLinkSQL = `DELETE FROM live_links WHERE id = ?`
	delDeadLinkSQL = `DELETE FROM dead_links WHERE id = ?`
)

// sqliteStore writes results into a SQLite database. Writes are grouped into
// one transaction per flushEvery results: a transaction per row would cost a
// sync each, and one for the whole run would lose everything to a crash.
type sqliteStore struct {
	db   *sql.DB
	tx   *sql.Tx
	stmt struct {
		putLive, putDead, delLive, delDead                 *sql.Stmt
		putLiveLink, putDeadLink, delLiveLink, delDeadLink *sql.Stmt
	}
	n      int
	closed bool
}

// NewSQLite opens the database at path, creating it and its tables if they
// are missing. Unlike the file stores it never truncates: every run adds to
// what earlier runs recorded.
func NewSQLite(path string) (Store, error) {
	if path == "" || path == "-" {
		return nil, errors.New("the database must be a file")
	}
	// The driver reads everything after a '?' as connection parameters.
	if strings.ContainsRune(path, '?') {
		return nil, errors.New("database path must not contain '?'")
	}
	// WAL lets a reader (the sqlite3 shell, say) query the file while a run
	// writes to it. With WAL, synchronous=NORMAL can lose only the last
	// transactions to a power cut, never corrupt the file.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One goroutine writes, so one connection is all it needs, and the
	// pragmas above are set once rather than per pooled connection.
	db.SetMaxOpenConns(1)
	// Also the first real touch of the file: a path that is not a database
	// fails here, before anything is written.
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	s := &sqliteStore{db: db}
	if err := s.begin(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// begin starts the next batch. It takes no context on purpose: a transaction
// begun with one is rolled back when that context ends, and an interrupt must
// not throw away the results already finished in this batch. Close commits
// them.
func (s *sqliteStore) begin() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, p := range []struct {
		dst   **sql.Stmt
		query string
	}{
		{&s.stmt.putLive, putLiveSQL},
		{&s.stmt.putDead, putDeadSQL},
		{&s.stmt.delLive, delLiveSQL},
		{&s.stmt.delDead, delDeadSQL},
		{&s.stmt.putLiveLink, putLiveLinkSQL},
		{&s.stmt.putDeadLink, putDeadLinkSQL},
		{&s.stmt.delLiveLink, delLiveLinkSQL},
		{&s.stmt.delDeadLink, delDeadLinkSQL},
	} {
		// Prepared on the transaction, so they are closed with it.
		if *p.dst, err = tx.Prepare(p.query); err != nil {
			tx.Rollback()
			return err
		}
	}
	s.tx = tx
	return nil
}

// commit ends the current batch, if there is one.
func (s *sqliteStore) commit() error {
	if s.tx == nil {
		return nil
	}
	tx := s.tx
	s.tx = nil
	return tx.Commit()
}

func (s *sqliteStore) Write(ctx context.Context, r probe.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.tx == nil { // a previous batch failed to start
		return errors.New("database is not writable")
	}
	var err error
	if r.Proxy.Link != nil {
		err = s.writeLink(r)
	} else {
		err = s.writeProxy(r)
	}
	if err != nil {
		return err
	}
	s.n++
	if s.n%flushEvery == 0 {
		if err := s.commit(); err != nil {
			return err
		}
		return s.begin()
	}
	return nil
}

// writeProxy moves a classic proxy into the table for its outcome.
func (s *sqliteStore) writeProxy(r probe.Result) error {
	rec := newRecord(r)
	port := int(rec.Port)
	at := rec.CheckedAt.Format(time.RFC3339Nano)
	var err error
	switch {
	case r.LeftOut:
		if _, err = s.stmt.delLive.Exec(rec.Host, port); err == nil {
			_, err = s.stmt.delDead.Exec(rec.Host, port)
		}
	case rec.Alive:
		if _, err = s.stmt.delDead.Exec(rec.Host, port); err == nil {
			_, err = s.stmt.putLive.Exec(rec.Host, port, rec.Protocol, rec.ConnectMS, rec.TotalMS,
				null(rec.ExitIP), null(rec.Country), null(int64(rec.ASN)), at)
		}
	default:
		if _, err = s.stmt.delLive.Exec(rec.Host, port); err == nil {
			_, err = s.stmt.putDead.Exec(rec.Host, port, rec.ConnectMS, null(rec.Error), at)
		}
	}
	return err
}

// writeLink moves a share link into the table for its outcome.
func (s *sqliteStore) writeLink(r probe.Result) error {
	rec := newRecord(r)
	id := r.Proxy.Link.ID()
	at := rec.CheckedAt.Format(time.RFC3339Nano)
	var err error
	switch {
	case r.LeftOut:
		if _, err = s.stmt.delLiveLink.Exec(id); err == nil {
			_, err = s.stmt.delDeadLink.Exec(id)
		}
	case rec.Alive:
		if _, err = s.stmt.delDeadLink.Exec(id); err == nil {
			_, err = s.stmt.putLiveLink.Exec(id, rec.Protocol, rec.Transport, rec.Security, rec.Host, int(rec.Port),
				null(rec.Name), rec.Link, rec.ConnectMS, rec.TotalMS,
				null(rec.ExitIP), null(rec.Country), null(int64(rec.ASN)), at)
		}
	default:
		if _, err = s.stmt.delLiveLink.Exec(id); err == nil {
			_, err = s.stmt.putDeadLink.Exec(id, rec.Protocol, rec.Transport, rec.Security, rec.Host, int(rec.Port),
				null(rec.Name), rec.Link, rec.ConnectMS, null(rec.Error), at)
		}
	}
	return err
}

func (s *sqliteStore) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.commit()
	if cerr := s.db.Close(); err == nil {
		err = cerr
	}
	return err
}

// null stores a zero value as NULL, so an unknown field reads as unknown
// rather than as an empty string or ASN 0.
func null[T comparable](v T) any {
	var zero T
	if v == zero {
		return nil
	}
	return v
}
