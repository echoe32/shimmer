// Command shimmer checks a list of proxies concurrently and writes what it found.
//
//	shimmer -i proxies.txt -o alive.jsonl -workers 512 -exit-ip
//
// The list is read as a stream and the results are written as a stream, so a
// run over a multi-million-line file holds only the in-flight probes in memory.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"shimmer/internal/config"
	"shimmer/internal/geo"
	"shimmer/internal/pipeline"
	"shimmer/internal/probe"
	"shimmer/internal/resume"
	"shimmer/internal/source"
	"shimmer/internal/store"
	"shimmer/internal/xray"
)

// maxPanicReports bounds the stacks printed when probes crash. One stack says
// what the bug is; a million of them bury the rest of the run.
const maxPanicReports = 3

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		var usage usageError
		switch {
		case errors.Is(err, flag.ErrHelp):
			return // -h: the usage is printed, and asking for it is no failure
		case errors.As(err, &usage):
			os.Exit(2) // already printed, with the usage
		case errors.Is(err, context.Canceled):
			os.Exit(130) // interrupted
		}
		fmt.Fprintln(os.Stderr, "shimmer:", err)
		os.Exit(1)
	}
}

// usageError is a command line the flag package rejected. The flag package
// has printed it already, so main only sets the exit status; printing it again
// showed every mistyped flag twice.
type usageError struct{ error }

func (e usageError) Unwrap() error { return e.error }

// feeder is a proxy source that also reports what it read. Both the local
// file and the remote-list source qualify.
type feeder interface {
	source.Source
	Read() int64
	Skipped() int64
	Err() error
	Close() error
}

func run(ctx context.Context) error {
	opt, err := settings()
	if err != nil {
		return err
	}
	cfg, aliveOnly, quiet := opt.cfg, opt.aliveOnly, opt.quiet
	if err := distinctOutput(opt); err != nil {
		return err
	}

	lines, err := openSource(opt)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer lines.Close()

	// Resuming reads the results file back and appends to it, so the file is
	// its own checkpoint. Everything it already holds is skipped.
	mode := store.Truncate
	var done *resume.Set
	if opt.resume {
		if cfg.Output == "-" || cfg.Output == "" {
			return errors.New("-resume needs -o to name a file")
		}
		done, err = resume.Load(cfg.Output, cfg.Format)
		if err != nil {
			return fmt.Errorf("read previous results: %w", err)
		}
		mode = store.Append
		if !quiet {
			fmt.Fprintf(os.Stderr, "shimmer: resuming %s, %d proxies already done", cfg.Output, done.Len())
			if c := done.Corrupt(); c > 0 {
				// Ignored, not removed: only a torn last line is cut from the file.
				fmt.Fprintf(os.Stderr, ", %d unreadable records ignored", c)
			}
			fmt.Fprintln(os.Stderr)
		}
	}

	lookup, closeLookup, err := newLookup(cfg)
	if err != nil {
		return err
	}
	defer closeLookup()

	// The database is never emptied, but opening it can still fail, so it
	// goes before the results file too.
	var db store.Store
	if cfg.DB != "" {
		if db, err = store.NewSQLite(cfg.DB); err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		defer db.Close()
		// Checked once the database exists, so the file itself answers
		// however the two paths are spelled.
		if sameFile(cfg.Output, cfg.DB) {
			return fmt.Errorf("-o %s is also the -db; writing results there would destroy it", cfg.Output)
		}
	}

	// Share links are checked through an embedded Xray. It starts here, where
	// a failure still leaves the previous results alone.
	links, err := xray.New()
	if err != nil {
		return err
	}
	defer links.Close()

	// Opened after everything that can refuse to start: in Truncate mode this
	// empties the previous results. With only -db given there is none.
	var out store.Store
	if cfg.Output != "" {
		if out, err = store.Open(cfg.Output, cfg.Format, mode); err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		defer out.Close()
	}

	probers, skipped, err := probe.LadderSkipping(probe.DefaultCheck, cfg.SkipProtocols)
	if err != nil {
		return err
	}
	workers := capWorkers(cfg.Workers, quiet)
	dialer := &net.Dialer{
		Timeout:   cfg.ProxyTimeout,
		KeepAlive: -1, // every probe connection is short-lived
	}
	p := pipeline.New(dialer, pipeline.Options{
		Workers:      workers,
		ProxyTimeout: cfg.ProxyTimeout,
		Probers:      probers,
		Skipped:      skipped,
		Geo:          lookup,
		CheckExitIP:  cfg.CheckExitIP,
		Links:        links,
		Check:        probe.DefaultCheck,
		Skip:         cfg.SkipProtocols,
		OnPanic:      panicReporter(),
	})

	// The workers get a context of their own, so a failed write can stop them
	// without looking like an interrupt.
	work, stop := context.WithCancel(ctx)
	defer stop()

	proxies, err := lines.Proxies(work)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	proxies = done.Filter(work, proxies)

	stopProgress := func() {}
	if !quiet {
		stopProgress = progress(ctx, p, lines)
		defer stopProgress()
	}

	start := time.Now()
	written, saved, err := record(work, stop, p.Run(work, proxies), out, db, aliveOnly)
	if err != nil {
		return fmt.Errorf("write result: %w", err)
	}

	// A list mirror that cannot be read costs only its own proxies. A local
	// list that fails part way is another matter: the rest of it was never
	// checked, so the run has not done its job, whatever it wrote.
	var inputErr error
	if err := lines.Err(); err != nil {
		if _, remote := lines.(*source.URLs); remote && lines.Read() > 0 {
			fmt.Fprintf(os.Stderr, "shimmer: part of the input was not read: %v\n", err)
		} else {
			inputErr = fmt.Errorf("read input: %w", err)
		}
	}
	// Flush before the summary claims anything about the file.
	if out != nil {
		if err := out.Close(); err != nil {
			return fmt.Errorf("close output: %w", err)
		}
	}
	if db != nil {
		if err := db.Close(); err != nil {
			return fmt.Errorf("close db: %w", err)
		}
	}
	// The summary is written piece by piece, and a progress line could land
	// in the middle of it.
	stopProgress()
	if !quiet {
		fmt.Fprintf(os.Stderr, "checked %d, alive %d", p.Checked(), p.Alive())
		if out != nil {
			fmt.Fprintf(os.Stderr, ", written %d", written)
		}
		if db != nil {
			fmt.Fprintf(os.Stderr, ", saved %d to db", saved)
		}
		fmt.Fprintf(os.Stderr, ", skipped %d bad lines", lines.Skipped())
		if n := done.Skipped(); n > 0 {
			fmt.Fprintf(os.Stderr, ", skipped %d already done", n)
		}
		if n := p.LeftOut(); n > 0 {
			fmt.Fprintf(os.Stderr, ", left out %d of skipped protocols", n)
		}
		if n := p.Panics(); n > 0 {
			fmt.Fprintf(os.Stderr, ", %d probes panicked", n)
		}
		fmt.Fprintf(os.Stderr, ", in %s\n", time.Since(start).Round(time.Millisecond))
	}
	if inputErr != nil {
		return inputErr
	}
	return ctx.Err()
}

// record writes results as they arrive and returns only once the pipeline has
// stopped, however it ends: the workers still use the geo databases, the
// dialer and the source, and the caller closes those next. A failed write
// stops the workers through stop; an interrupt has stopped them already.
//
// Either store may be nil. The database takes every result: -alive-only
// shapes the results file, and the database keeps the dead apart already.
// A result marked LeftOut goes only to the database, which removes its proxy,
// and counts as neither written nor saved.
func record(ctx context.Context, stop context.CancelFunc, results <-chan probe.Result, out, db store.Store, aliveOnly bool) (written, saved int64, err error) {
	defer func() {
		stop()
		for range results { //nolint:revive // waiting for the workers to finish
		}
	}()
	for res := range results {
		if db != nil {
			if err := db.Write(ctx, res); err != nil {
				return written, saved, writeFailure(fmt.Errorf("db: %w", err))
			}
			if !res.LeftOut {
				saved++
			}
		}
		if out == nil || res.LeftOut || aliveOnly && !res.Alive {
			continue
		}
		if err := out.Write(ctx, res); err != nil {
			return written, saved, writeFailure(err)
		}
		written++
	}
	return written, saved, nil
}

// writeFailure is the error record returns for a failed write. A write
// refused because of an interrupt is none: the caller reports the interrupt.
func writeFailure(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// sameFile reports whether the results path names the file at path. Stdout
// is no file, and a path that does not exist yet is not one that does.
func sameFile(out, path string) bool {
	if out == "-" || out == "" {
		return false
	}
	a, err := os.Stat(out)
	if err != nil {
		return false
	}
	b, err := os.Stat(path)
	return err == nil && os.SameFile(a, b)
}

// options is everything one run needs: the shared config plus the settings
// that only the command line carries.
type options struct {
	cfg       config.Config
	config    string // the config file loaded, empty for none
	env       string // the .env file read, empty for none
	lists     string // file of list URLs, instead of a file of proxies
	fetch     int    // concurrent list downloads
	resume    bool   // skip what the output file already holds, and append
	aliveOnly bool
	quiet     bool
}

// distinctOutput refuses a results file that is also a file the run reads, or
// its database, however the two paths are spelled. Opening the output empties it, so the
// list would be gone before a line of it was read. A geo database is worse:
// the reader maps it, and the first lookup into the emptied file kills the
// process with a bus error that no recover can catch.
func distinctOutput(opt options) error {
	out := opt.cfg.Output
	if out == "-" || out == "" {
		return nil
	}
	outInfo, err := os.Stat(out)
	if err != nil {
		return nil // nothing there to lose; opening it reports any real trouble
	}
	var inInfo os.FileInfo
	switch {
	case opt.lists != "":
		inInfo, err = os.Stat(opt.lists)
	case opt.cfg.Input == "-" || opt.cfg.Input == "":
		inInfo, err = os.Stdin.Stat() // shimmer -o list.txt < list.txt
	default:
		inInfo, err = os.Stat(opt.cfg.Input)
	}
	if err == nil && os.SameFile(inInfo, outInfo) {
		return fmt.Errorf("-o %s is also the input; writing results there would destroy it", out)
	}
	for _, read := range []struct{ what, path string }{
		{"-mmdb-city database", opt.cfg.MMDBCity},
		{"-mmdb-asn database", opt.cfg.MMDBASN},
		{"-config file", opt.config},
		{"-env file", opt.env},
		// Before the database is opened: SQLite takes an empty file for a
		// database with nothing in it yet, and made one of it. run checks
		// again once the database exists, for a path that names no file yet.
		{"-db", opt.cfg.DB},
	} {
		if read.path == "" {
			continue
		}
		if info, err := os.Stat(read.path); err == nil && os.SameFile(info, outInfo) {
			return fmt.Errorf("-o %s is also the %s; writing results there would destroy it", out, read.what)
		}
	}
	return nil
}

// openSource picks the file of proxies or the file of list links.
func openSource(opt options) (feeder, error) {
	if opt.lists != "" {
		u, err := source.OpenURLs(opt.lists)
		if err != nil {
			return nil, err
		}
		u.Fetch = opt.fetch
		return u, nil
	}
	return source.Open(opt.cfg.Input)
}

// settings assembles the config file, the SHIMMER_ variables and the flags, each
// overriding the one before. Only flags actually typed or set by a variable
// count, so a config file is not silently overwritten by defaults.
func settings() (options, error) {
	fs := flag.NewFlagSet("shimmer", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: shimmer -i proxies.txt [-o results.jsonl] [options]\n")
		fmt.Fprintf(fs.Output(), "       (a list holds classic proxies, share links (vless://, vmess://, trojan://, ss://, hy2://), or both)\n")
		fmt.Fprintf(fs.Output(), "       shimmer -lists urls.txt  -o results.jsonl [options]\n")
		fmt.Fprintf(fs.Output(), "       shimmer -i proxies.txt -db results.db [options]\n\n")
		fs.PrintDefaults()
	}

	var (
		configPath = fs.String("config", "", "JSON config file to load before the flags")
		envPath    = fs.String("env", ".env", "file of SHIMMER_ variables, read if it exists; \"\" reads none")
		input      = fs.String("i", "-", "proxy list file, one per line (\"-\" is stdin)")
		lists      = fs.String("lists", "", "file of list URLs to download, one per line, instead of -i")
		fetch      = fs.Int("fetch", 4, "concurrent list downloads, with -lists")
		output     = fs.String("o", "-", "results file (\"-\" is stdout); with only -db given, none is written")
		dbPath     = fs.String("db", "", "SQLite database that keeps every result across runs, live and dead proxies in separate tables")
		format     = fs.String("format", "jsonl", "output format: jsonl or csv")
		workers    = fs.Int("workers", 512, "concurrent probes")
		timeout    = fs.Duration("timeout", 10*time.Second, "per-proxy deadline across all attempts")
		city       = fs.String("mmdb-city", "", "MaxMind City database, for the country field")
		asn        = fs.String("mmdb-asn", "", "MaxMind ASN database, for the ASN field")
		exitIP     = fs.Bool("exit-ip", false, "ask an echo endpoint for the true exit IP of each live proxy; exit_ip, country and asn stay empty when it cannot tell")
		skip       = fs.String("skip", "", "protocols not to record, comma-separated: socks5, socks4, https, http, vless, vmess, trojan, ss, hysteria2; a classic proxy's are tried last, only to leave out proxies that speak nothing else")
		keepGoing  = fs.Bool("resume", false, "continue an interrupted run: skip proxies already in -o, append the rest")
		onlyAlive  = fs.Bool("alive-only", false, "write live proxies only")
		beQuiet    = fs.Bool("quiet", false, "no progress or summary on stderr")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return options{}, usageError{err}
	}
	// The flag package stops at the first argument that is no flag and leaves
	// the rest unread: "-quiet true -o out.jsonl" ran with no -o at all, and
	// "shimmer proxies.txt" waited on stdin. Reported the way the flag
	// package reports its own.
	if fs.NArg() > 0 {
		err := fmt.Errorf("unexpected argument %q: every setting is a flag, and the list is named with -i", fs.Arg(0))
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return options{}, usageError{err}
	}
	envRead, err := applyEnv(fs, *envPath)
	if err != nil {
		return options{}, err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return options{}, err
	}
	// Only flags the user actually set, or a variable set for them, override
	// the file.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "i":
			cfg.Input = *input
		case "o":
			cfg.Output = *output
		case "db":
			cfg.DB = *dbPath
		case "format":
			cfg.Format = *format
		case "workers":
			cfg.Workers = *workers
		case "timeout":
			cfg.ProxyTimeout = *timeout
		case "mmdb-city":
			cfg.MMDBCity = *city
		case "mmdb-asn":
			cfg.MMDBASN = *asn
		case "exit-ip":
			cfg.CheckExitIP = *exitIP
		case "skip":
			cfg.SkipProtocols = splitProtocols(*skip)
		}
	})
	if cfg.Input == "" {
		cfg.Input = *input
	}
	// Results go to stdout unless something else was asked for: a run with
	// only a database writes no results file, rather than flooding stdout.
	// An empty -o means no -o, as an empty "output" in the file does; taken
	// as typed, it wrote the results nowhere at all.
	if cfg.Output == "" && cfg.DB == "" {
		cfg.Output = "-"
	}
	if err := cfg.Validate(); err != nil {
		return options{}, err
	}
	return options{
		cfg:       cfg,
		config:    *configPath,
		env:       envRead,
		lists:     *lists,
		fetch:     *fetch,
		resume:    *keepGoing,
		aliveOnly: *onlyAlive,
		quiet:     *beQuiet,
	}, nil
}

// splitProtocols reads the -skip list. Blank entries are dropped, so -skip ""
// clears a list set in the config file.
func splitProtocols(list string) []probe.Protocol {
	var out []probe.Protocol
	for name := range strings.SplitSeq(list, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, probe.Protocol(name))
		}
	}
	return out
}

type envName struct{ flag, name string }

// envNames pairs each flag the environment and the .env file can set with its
// variable. -lists and -resume have none: each changes what a run does, and
// one left in the file would quietly change every run after it.
var envNames = []envName{
	{"config", "SHIMMER_CONFIG"},
	{"i", "SHIMMER_INPUT"},
	{"fetch", "SHIMMER_FETCH"},
	{"o", "SHIMMER_OUTPUT"},
	{"db", "SHIMMER_DB"},
	{"format", "SHIMMER_FORMAT"},
	{"workers", "SHIMMER_WORKERS"},
	{"timeout", "SHIMMER_TIMEOUT"},
	{"mmdb-city", "SHIMMER_MMDB_CITY"},
	{"mmdb-asn", "SHIMMER_MMDB_ASN"},
	{"exit-ip", "SHIMMER_EXIT_IP"},
	{"skip", "SHIMMER_SKIP"},
	{"alive-only", "SHIMMER_ALIVE_ONLY"},
	{"quiet", "SHIMMER_QUIET"},
}

// applyEnv sets every flag that was not typed from its variable: the
// environment's value if it has one, else the .env file's. A flag set this
// way counts as given, so it overrides the config file, and it is parsed as
// the flag is. Empty values are ignored. It returns the .env file it read:
// the default one is optional, a -env that was typed is not.
func applyEnv(fs *flag.FlagSet, path string) (string, error) {
	typed := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { typed[f.Name] = true })

	var file map[string]string
	if path != "" {
		var err error
		file, err = config.ReadEnvFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist) && !typed["env"]:
			path = ""
		case err != nil:
			return "", err
		}
	}
	// A misspelt name in the file would leave its setting at the default
	// without a word. The environment is not checked: it is not ours.
	for _, name := range slices.Sorted(maps.Keys(file)) {
		if strings.HasPrefix(name, "SHIMMER_") && !slices.ContainsFunc(envNames, func(e envName) bool { return e.name == name }) {
			return "", fmt.Errorf("parse %s: unknown variable %s", path, name)
		}
	}
	for _, e := range envNames {
		if typed[e.flag] {
			continue
		}
		v := os.Getenv(e.name)
		if v == "" {
			v = file[e.name]
		}
		if v == "" {
			continue
		}
		if err := fs.Set(e.flag, v); err != nil {
			return "", fmt.Errorf("invalid value %q for %s: %w", v, e.name, err)
		}
	}
	return path, nil
}

// panicReporter prints the first few probe crashes, with their stacks, and
// then stays quiet. A crashed probe is already recorded as a dead proxy; this
// is only so the bug behind it is not invisible. It ignores -quiet, which is
// about progress, not about bugs.
func panicReporter() func(probe.Proxy, any, []byte) {
	var seen atomic.Int64
	return func(px probe.Proxy, v any, stack []byte) {
		n := seen.Add(1)
		if n > maxPanicReports {
			return
		}
		fmt.Fprintf(os.Stderr, "shimmer: probe of %s panicked: %v\n%s", px, v, stack)
		if n == maxPanicReports {
			fmt.Fprintln(os.Stderr, "shimmer: further probe panics will not be printed")
		}
	}
}

// newLookup opens the MaxMind databases, if any were given.
func newLookup(cfg config.Config) (geo.Lookup, func(), error) {
	if cfg.MMDBCity == "" && cfg.MMDBASN == "" {
		return nil, func() {}, nil
	}
	l, err := geo.NewMMDB(cfg.MMDBCity, cfg.MMDBASN)
	if err != nil {
		return nil, func() {}, err
	}
	closer := func() {
		if c, ok := l.(io.Closer); ok {
			c.Close()
		}
	}
	return l, closer, nil
}

// progress reports how the run is going every few seconds. It writes to
// stderr, so piping the results to another program stays clean. The func it
// returns stops the reports and waits for one being written; it may be called
// more than once.
func progress(ctx context.Context, p *pipeline.Pipeline, lines feeder) func() {
	t := time.NewTicker(2 * time.Second)
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		start := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				checked := p.Checked()
				rate := float64(checked) / time.Since(start).Seconds()
				fmt.Fprintf(os.Stderr, "read %d, checked %d, alive %d, %.0f/s\n",
					lines.Read(), checked, p.Alive(), rate)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.Stop()
			close(done)
		})
		<-exited
	}
}

// capWorkers keeps the pool inside the open-file limit. Every in-flight probe
// holds a socket, and the default limit on macOS is smaller than the default
// worker count.
func capWorkers(want int, quiet bool) int {
	limit, ok := fileLimit()
	if !ok {
		return want
	}
	const headroom = 32 // stdin/stdout, the output file, the geo databases
	// An unlimited limit does not fit an int on 32-bit platforms, and came
	// out negative: one worker.
	max := int(min(limit, math.MaxInt)) - headroom
	if max < 1 {
		max = 1
	}
	if want <= max {
		return want
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "shimmer: open-file limit is %d, running %d workers instead of %d\n",
			limit, max, want)
	}
	return max
}
