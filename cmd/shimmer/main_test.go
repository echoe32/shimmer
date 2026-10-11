package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"shimmer/internal/dial"
	"shimmer/internal/geo"
	"shimmer/internal/pipeline"
	"shimmer/internal/probe"
)

// A mistyped database path used to fail only after the output had been
// opened, and so emptied, in Truncate mode.
func TestBadGeoDatabaseLeavesResultsAlone(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "proxies.txt")
	results := filepath.Join(dir, "results.jsonl")
	previous := `{"host":"1.2.3.4","port":80,"alive":true}` + "\n"
	if err := os.WriteFile(input, []byte("127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(results, []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}

	args := os.Args
	t.Cleanup(func() { os.Args = args })
	os.Args = []string{"shimmer", "-quiet", "-i", input, "-o", results, "-mmdb-city", filepath.Join(dir, "typo.mmdb")}

	if err := run(context.Background()); err == nil {
		t.Fatal("run succeeded with a missing database")
	}
	data, err := os.ReadFile(results)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != previous {
		t.Errorf("results file is now %q, want it untouched", data)
	}
}

// withArgs runs the rest of the test with os.Args set to a command line.
func withArgs(t *testing.T, args ...string) {
	t.Helper()
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = append([]string{"shimmer"}, args...)
}

// Opening the output empties it. When it was also the input, the list was
// gone before a line of it had been read.
func TestOutputThatIsTheInputIsRefused(t *testing.T) {
	dir := t.TempDir()
	proxies := filepath.Join(dir, "proxies.txt")
	links := filepath.Join(dir, "lists.txt")
	const proxyBody, linkBody = "127.0.0.1:1\n", "https://example.com/list.txt\n"
	sameProxies := filepath.Join(dir, ".", "sub", "..", "proxies.txt") // spelled differently
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, path, body string
		args             []string
		stdin            bool
	}{
		{"input", proxies, proxyBody, []string{"-i", proxies, "-o", sameProxies}, false},
		{"input, resumed", proxies, proxyBody, []string{"-resume", "-i", proxies, "-o", proxies}, false},
		{"stdin", proxies, proxyBody, []string{"-o", proxies}, true},
		{"lists", links, linkBody, []string{"-lists", links, "-o", links}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(c.path, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if c.stdin {
				f, err := os.Open(c.path)
				if err != nil {
					t.Fatal(err)
				}
				saved := os.Stdin
				os.Stdin = f
				t.Cleanup(func() { os.Stdin = saved; f.Close() })
			}
			withArgs(t, append([]string{"-quiet"}, c.args...)...)

			if err := run(context.Background()); err == nil {
				t.Error("run accepted an output that is also the input")
			}
			data, err := os.ReadFile(c.path)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != c.body {
				t.Errorf("input is now %q, want it untouched", data)
			}
		})
	}
}

// The input is not the only file the output can destroy. A geo database
// emptied by -o also took the process down at the first lookup: the reader
// maps the file, and reading past its new end is a bus error.
func TestOutputThatIsAFileTheRunReadsIsRefused(t *testing.T) {
	dir := t.TempDir()
	proxies := filepath.Join(dir, "proxies.txt")
	if err := os.WriteFile(proxies, []byte("127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, flag, file, body string
	}{
		{"city database", "-mmdb-city", "city.mmdb", "a database"},
		{"ASN database", "-mmdb-asn", "asn.mmdb", "a database"},
		{"config file", "-config", "shimmer.json", "{}"},
		{".env file", "-env", "shimmer.env", "# no settings\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, c.file)
			if err := os.WriteFile(path, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			withArgs(t, "-quiet", "-i", proxies, c.flag, path, "-o", dir+"/./"+c.file)

			err := run(context.Background())
			if err == nil || !strings.Contains(err.Error(), "would destroy it") {
				t.Errorf("err = %v, want the output refused", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != c.body {
				t.Errorf("%s is now %q, want it untouched", c.file, data)
			}
		})
	}
}

// An empty -o is no -o, as an empty "output" in the config file is: results
// go to stdout, or with -db only to the database. Taken as typed, it wrote
// them nowhere at all.
func TestEmptyOutputFlagMeansNone(t *testing.T) {
	withArgs(t, "-o", "")
	opt, err := settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if opt.cfg.Output != "-" {
		t.Errorf("output %q, want stdout", opt.cfg.Output)
	}

	withArgs(t, "-o", "", "-db", filepath.Join(t.TempDir(), "shimmer.db"))
	if opt, err = settings(); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if opt.cfg.Output != "" {
		t.Errorf("output %q, want none beside the database", opt.cfg.Output)
	}
}

// Flags override the config file, so a flag must be able to correct a value
// the file got wrong. The file used to be validated before the flags applied.
func TestFlagCorrectsConfigFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "shimmer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"workers":0,"format":"xml"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	withArgs(t, "-config", cfgPath, "-workers", "8", "-format", "csv")
	opt, err := settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if opt.cfg.Workers != 8 || opt.cfg.Format != "csv" {
		t.Errorf("workers %d, format %q; want the flags' 8 and csv", opt.cfg.Workers, opt.cfg.Format)
	}

	withArgs(t, "-config", cfgPath, "-workers", "8")
	if _, err := settings(); err == nil {
		t.Error("the file's bad format was accepted with no flag to correct it")
	}
}

// -skip replaces the file's list, and an empty -skip clears it.
func TestSkipFlagOverridesConfigFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "shimmer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"skip_protocols":["socks4"]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	withArgs(t, "-config", cfgPath, "-skip", " https, http,")
	opt, err := settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if want := []probe.Protocol{probe.HTTPS, probe.HTTP}; !slices.Equal(opt.cfg.SkipProtocols, want) {
		t.Errorf("skip %v, want %v", opt.cfg.SkipProtocols, want)
	}

	withArgs(t, "-config", cfgPath, "-skip", "")
	if opt, err = settings(); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if len(opt.cfg.SkipProtocols) != 0 {
		t.Errorf("skip %v, want the file's list cleared", opt.cfg.SkipProtocols)
	}

	withArgs(t, "-skip", "socks5,socks4,https,http,vless,vmess,trojan,ss,hysteria2")
	if _, err := settings(); err == nil {
		t.Error("skipping every protocol was accepted")
	}

	// Every classic protocol skipped still leaves share links to find.
	withArgs(t, "-skip", "socks5,socks4,https,http")
	if _, err := settings(); err != nil {
		t.Errorf("skipping the classic protocols: %v", err)
	}
}

// Each layer overrides the one before: config file, .env file, environment,
// typed flags.
func TestEnvOverridesConfigFileAndFlagsOverrideEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "shimmer.json")
	envPath := filepath.Join(dir, "shimmer.env")
	if err := os.WriteFile(cfgPath, []byte(`{"workers":1,"format":"csv","db":"file.db","skip_protocols":["socks4"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env := "SHIMMER_WORKERS=2\nSHIMMER_FORMAT=jsonl\nSHIMMER_TIMEOUT=3s\nSHIMMER_EXIT_IP=true\nSHIMMER_SKIP=http\nSHIMMER_DB=\nTZ=UTC\n"
	if err := os.WriteFile(envPath, []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, e := range envNames {
		t.Setenv(e.name, "")
	}
	t.Setenv("SHIMMER_WORKERS", "3")

	withArgs(t, "-env", envPath, "-config", cfgPath, "-format", "csv")
	opt, err := settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	cfg := opt.cfg
	if cfg.Workers != 3 {
		t.Errorf("workers %d, want the environment's 3", cfg.Workers)
	}
	if cfg.Format != "csv" {
		t.Errorf("format %q, want the flag's csv", cfg.Format)
	}
	if cfg.ProxyTimeout != 3*time.Second || !cfg.CheckExitIP {
		t.Errorf("timeout %s, exit-ip %v; want the .env file's 3s and true", cfg.ProxyTimeout, cfg.CheckExitIP)
	}
	if want := []probe.Protocol{probe.HTTP}; !slices.Equal(cfg.SkipProtocols, want) {
		t.Errorf("skip %v, want the .env file's %v", cfg.SkipProtocols, want)
	}
	if cfg.DB != "file.db" {
		t.Errorf("db %q, want the config file's: an empty variable is no value", cfg.DB)
	}
	if opt.env != envPath {
		t.Errorf("env file %q, want %q", opt.env, envPath)
	}
}

func TestEnvFileMistakesAreRefused(t *testing.T) {
	dir := t.TempDir()
	for _, e := range envNames {
		t.Setenv(e.name, "")
	}
	for _, body := range []string{
		"SHIMMER_WORKRS=64\n",    // misspelt
		"SHIMMER_RESUME=true\n",  // flag only
		"SHIMMER_WORKERS=many\n", // not a number
		"SHIMMER_EXIT_IP=yes\n",  // not a bool
		"SHIMMER_TIMEOUT=soon\n", // not a duration
		"SHIMMER_SKIP=socks6\n",  // no such protocol
		"SHIMMER_WORKERS 64\n",   // no =
	} {
		envPath := filepath.Join(dir, "shimmer.env")
		if err := os.WriteFile(envPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		withArgs(t, "-env", envPath)
		if _, err := settings(); err == nil {
			t.Errorf("settings accepted a .env file of %q", body)
		}
	}

	withArgs(t, "-env", filepath.Join(dir, "missing.env"))
	if _, err := settings(); err == nil {
		t.Error("a -env file that does not exist was accepted")
	}
}

// The default .env is read from the current directory, and only if it is
// there.
func TestDefaultEnvFileIsOptional(t *testing.T) {
	for _, e := range envNames {
		t.Setenv(e.name, "")
	}
	t.Chdir(t.TempDir())

	withArgs(t)
	opt, err := settings()
	if err != nil {
		t.Fatalf("settings without a .env file: %v", err)
	}
	if opt.env != "" {
		t.Errorf("env file %q, want none", opt.env)
	}

	if err := os.WriteFile(".env", []byte("SHIMMER_WORKERS=7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if opt, err = settings(); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if opt.cfg.Workers != 7 || opt.env != ".env" {
		t.Errorf("workers %d from %q, want 7 from .env", opt.cfg.Workers, opt.env)
	}

	withArgs(t, "-env", "")
	if opt, err = settings(); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if opt.cfg.Workers != 512 || opt.env != "" {
		t.Errorf("-env \"\": workers %d from %q, want the default and no file", opt.cfg.Workers, opt.env)
	}
}

// mainEnv marks the child process that runMain starts to run main.
const mainEnv = "SHIMMER_TEST_RUN_MAIN"

// runMain runs main in a child process with args, the way the command runs,
// and reports its exit status and what it wrote to stderr.
func runMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestMainProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), mainEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return exit.ExitCode(), stderr.String()
	case err != nil:
		t.Fatalf("run main: %v", err)
	}
	return 0, stderr.String()
}

// TestMainProcess is main itself, in the child process runMain starts.
func TestMainProcess(t *testing.T) {
	if os.Getenv(mainEnv) != "1" {
		t.Skip("runs only as runMain's child")
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	os.Args = append([]string{"shimmer"}, args...)
	main()
}

// -h used to exit 1 with "shimmer: flag: help requested", and a mistyped flag had
// its error printed twice: once by the flag package, with the usage, and once
// more by main.
func TestCommandLineMistakesAreReportedOnce(t *testing.T) {
	code, stderr := runMain(t, "-h")
	if code != 0 {
		t.Errorf("-h exited %d, want 0", code)
	}
	if strings.Contains(stderr, "help requested") {
		t.Errorf("-h reported an error:\n%s", stderr)
	}

	code, stderr = runMain(t, "-bogus")
	if code != 2 {
		t.Errorf("unknown flag exited %d, want 2", code)
	}
	if n := strings.Count(stderr, "-bogus"); n != 1 {
		t.Errorf("unknown flag named %d times, want once:\n%s", n, stderr)
	}
}

// The flag package stops reading at the first argument that is no flag. What
// followed it was dropped without a word: "-quiet true -o out.jsonl" ran with
// no -o and wrote the results to stdout, and "shimmer proxies.txt" read stdin.
func TestStrayArgumentIsRefused(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.jsonl")
	for _, args := range [][]string{
		{"-quiet", "stray-word", "-o", out},
		{"stray-word"},
	} {
		code, stderr := runMain(t, args...)
		if code != 2 {
			t.Errorf("%v exited %d, want 2", args, code)
		}
		if n := strings.Count(stderr, "stray-word"); n != 1 {
			t.Errorf("%v: stray argument named %d times, want once:\n%s", args, n, stderr)
		}
		if !strings.Contains(stderr, "usage: shimmer") {
			t.Errorf("%v: no usage printed:\n%s", args, stderr)
		}
	}
}

// After a failed write the caller closes the geo databases, and closing a
// MaxMind reader unmaps it. Workers still inside a lookup at that point read
// unmapped memory, so record must not return while any worker runs.
func TestRecordStopsPipelineBeforeReturning(t *testing.T) {
	g := &slowGeo{}
	p := pipeline.New(pipeDialer{}, pipeline.Options{
		Workers:      8,
		ProxyTimeout: time.Second,
		Probers:      []probe.Prober{aliveProber{}},
		Geo:          g,
	})
	in := make(chan probe.Proxy, 10_000)
	for i := range cap(in) {
		in <- probe.Proxy{Host: "192.0.2.1", Port: uint16(1 + i)}
	}
	close(in)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	_, _, err := record(ctx, stop, p.Run(ctx, in), failingStore{}, nil, false)

	if !errors.Is(err, errDiskFull) {
		t.Errorf("err = %v, want the write failure", err)
	}
	if n := g.inflight.Load(); n != 0 {
		t.Errorf("%d lookups still running after record returned", n)
	}
	calls := g.calls.Load()
	time.Sleep(50 * time.Millisecond)
	if n := g.calls.Load(); n != calls {
		t.Errorf("%d more lookups after record returned: the workers kept probing", n-calls)
	}
}

func TestRecordTreatsInterruptAsNoError(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()
	results := make(chan probe.Result, 1)
	results <- probe.Result{Alive: true}
	close(results)

	if _, _, err := record(ctx, stop, results, failingStore{}, nil, false); err != nil {
		t.Errorf("err = %v, want none: an interrupt is reported by the caller", err)
	}
}

// A left-out result goes to the database, which removes its proxy, and never
// to the results file; neither counts it.
func TestRecordSendsLeftOutOnlyToDatabase(t *testing.T) {
	results := make(chan probe.Result, 2)
	results <- probe.Result{Proxy: probe.Proxy{Host: "192.0.2.1", Port: 1}, Protocol: probe.SOCKS5, Alive: true}
	results <- probe.Result{Proxy: probe.Proxy{Host: "192.0.2.2", Port: 2}, Protocol: probe.SOCKS4, LeftOut: true}
	close(results)

	var out, db keptStore
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	written, saved, err := record(ctx, stop, results, &out, &db, false)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if written != 1 || saved != 1 {
		t.Errorf("written %d, saved %d; want 1 and 1", written, saved)
	}
	if len(out.got) != 1 || out.got[0].LeftOut {
		t.Errorf("results file got %+v, want the live proxy alone", out.got)
	}
	if len(db.got) != 2 || !db.got[1].LeftOut {
		t.Errorf("database got %+v, want both, the second left out", db.got)
	}
}

// keptStore keeps what it is handed.
type keptStore struct{ got []probe.Result }

func (s *keptStore) Write(_ context.Context, r probe.Result) error {
	s.got = append(s.got, r)
	return nil
}

func (s *keptStore) Close() error { return nil }

// pipeDialer connects to nothing, which is enough for the TCP reachability step.
type pipeDialer struct{}

func (pipeDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	return client, nil
}

type aliveProber struct{}

func (aliveProber) Name() probe.Protocol { return probe.SOCKS5 }

func (aliveProber) Probe(_ context.Context, _ dial.Dialer, p probe.Proxy) (*probe.Result, error) {
	return &probe.Result{Proxy: p, Protocol: probe.SOCKS5, Alive: true, CheckedAt: time.Now()}, nil
}

// slowGeo counts the lookups in flight, the ones a closed database would crash.
type slowGeo struct {
	inflight, calls atomic.Int64
}

func (g *slowGeo) Lookup(context.Context, netip.Addr) (*geo.Info, error) {
	g.inflight.Add(1)
	defer g.inflight.Add(-1)
	g.calls.Add(1)
	time.Sleep(2 * time.Millisecond)
	return &geo.Info{Country: "ZZ"}, nil
}

var errDiskFull = errors.New("no space left on device")

// failingStore refuses every write the way a full disk would; after an
// interrupt it reports the cancellation, as the real stores do.
type failingStore struct{}

func (failingStore) Write(ctx context.Context, _ probe.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errDiskFull
}

func (failingStore) Close() error { return nil }
