// Package xray carries connections through share links (vless, vmess,
// trojan, ss, hysteria2) with an embedded Xray-core.
//
// One Xray instance serves a whole run. Each link checked gets an outbound
// of its own, under a tag of its own, for as long as its check runs; every
// connection through it is routed to that outbound by tag, and nothing is
// routed any other way.
package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"

	_ "github.com/xtls/xray-core/main/distro/all" // every protocol and transport

	"shimmer/internal/dial"
	"shimmer/internal/link"
)

func init() {
	// Xray logs to stdout until told otherwise, and stdout carries results.
	// Why a link failed reaches the caller as an error instead.
	xlog.RegisterHandler(discard{})
}

type discard struct{}

func (discard) Handle(xlog.Message) {}

// sockets is the system dialer every Xray outbound connects through. There
// is one per process, because Xray has one.
var sockets = &tracker{
	base: &internet.DefaultSystemDialer{},
	live: make(map[string]map[net.Conn]struct{}),
}

var installDialer sync.Once

// Engine is one running Xray instance.
type Engine struct {
	inst *core.Instance
	om   outbound.Manager
	next atomic.Uint64
}

// New starts an instance with no inbounds and a single outbound that drops
// everything, so a connection whose tunnel has closed goes nowhere.
func New() (*Engine, error) {
	installDialer.Do(func() { internet.UseAlternativeSystemDialer(sockets) })
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:           "blocked",
			ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
		}},
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("start xray: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("start xray: %w", err)
	}
	om, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		inst.Close()
		return nil, errors.New("start xray: no outbound manager")
	}
	return &Engine{inst: inst, om: om}, nil
}

// Close stops the instance.
func (e *Engine) Close() error { return e.inst.Close() }

// Open adds an outbound for l. The tunnel it returns, a *Tunnel, dials
// through that outbound until it is closed.
func (e *Engine) Open(ctx context.Context, l *link.Link) (dial.Tunnel, error) {
	tag := "link-" + strconv.FormatUint(e.next.Add(1), 10)
	hc, err := build(l, tag)
	if err != nil {
		return nil, err
	}
	obj, err := core.CreateObject(e.inst, hc)
	if err != nil {
		return nil, fmt.Errorf("outbound: %w", err)
	}
	h, ok := obj.(outbound.Handler)
	if !ok {
		return nil, errors.New("outbound: not a handler")
	}
	sockets.open(tag)
	if err := e.om.AddHandler(ctx, h); err != nil {
		sockets.close(tag)
		h.Close()
		return nil, fmt.Errorf("outbound: %w", err)
	}
	return &Tunnel{e: e, h: h, tag: tag}, nil
}

// build turns a link into Xray's outbound configuration.
func build(l *link.Link, tag string) (*core.OutboundHandlerConfig, error) {
	raw, err := l.Outbound(tag)
	if err != nil {
		return nil, err
	}
	var dc conf.OutboundDetourConfig
	if err := json.Unmarshal(raw, &dc); err != nil {
		return nil, fmt.Errorf("outbound: %w", err)
	}
	hc, err := dc.Build()
	if err != nil {
		return nil, fmt.Errorf("outbound: %w", err)
	}
	if l.Insecure {
		if err := allowInsecure(hc); err != nil {
			return nil, fmt.Errorf("outbound: %w", err)
		}
	}
	return hc, nil
}

// allowInsecure turns off certificate verification in a built outbound. Xray
// refuses "allowInsecure" in JSON since 2026-06-01, but links still ask for
// it, and a client that honours them connects where a verifying one cannot.
func allowInsecure(hc *core.OutboundHandlerConfig) error {
	if hc.SenderSettings == nil {
		return nil
	}
	msg, err := hc.SenderSettings.GetInstance()
	if err != nil {
		return err
	}
	sender, ok := msg.(*proxyman.SenderConfig)
	if !ok || sender.StreamSettings == nil {
		return nil
	}
	for i, tm := range sender.StreamSettings.SecuritySettings {
		m, err := tm.GetInstance()
		if err != nil {
			return err
		}
		if t, ok := m.(*tls.Config); ok {
			t.AllowInsecure = true
			sender.StreamSettings.SecuritySettings[i] = serial.ToTypedMessage(t)
		}
	}
	hc.SenderSettings = serial.ToTypedMessage(sender)
	return nil
}

// Tunnel dials through one link's outbound. It satisfies dial.Dialer.
type Tunnel struct {
	e    *Engine
	h    outbound.Handler
	tag  string
	once sync.Once
}

// DialContext opens a TCP connection to addr through the link.
//
// Xray connects asynchronously: the call returns at once, and the handshake
// with the server runs behind it. A link that fails shows up as an error on
// the connection's first read, carrying Xray's reason.
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("link tunnel supports tcp only, got %q", network)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dest, err := xnet.ParseDestination("tcp:" + addr)
	if err != nil {
		return nil, err
	}
	// The connection outlives this call, so it gets a lifetime of its own:
	// its deadline and Close end it, not the caller's context.
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	errs := &firstError{}
	life = session.ContextWithContent(life, &session.Content{SkipDNSResolve: true}) // the server resolves names
	life = session.SetForcedOutboundTagToContext(life, t.tag)
	life = session.TrackedConnectionError(life, errs)
	c, err := core.Dial(life, t.e.inst, dest)
	if err != nil {
		cancel()
		return nil, err
	}
	conn := &conn{Conn: c, cancel: cancel, errs: errs}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	return conn, nil
}

// Close removes the link's outbound and closes every socket it opened.
func (t *Tunnel) Close() error {
	t.once.Do(func() {
		t.e.om.RemoveHandler(context.Background(), t.tag)
		t.h.Close()
		sockets.close(t.tag)
	})
	return nil
}

// firstError keeps the first failure Xray reports for a connection.
type firstError struct {
	mu  sync.Mutex
	err error
}

func (f *firstError) SubmitError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil {
		f.err = err
	}
}

func (f *firstError) get() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

// conn is a connection through Xray. Xray's own connection ignores
// deadlines, so conn enforces them by closing it when one passes. A
// connection past its deadline is no more use to a probe than a closed one.
type conn struct {
	net.Conn
	cancel context.CancelFunc
	errs   *firstError

	mu      sync.Mutex
	timer   *time.Timer
	expired bool
	cause   error // what Xray had reported when the deadline passed
}

func (c *conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		err = c.explain(err)
	}
	return n, err
}

func (c *conn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		err = c.explain(err)
	}
	return n, err
}

// explain replaces the bare EOF a failed outbound leaves behind with the
// reason Xray gave for it, and a read cut short by the deadline with a
// timeout.
func (c *conn) explain(err error) error {
	c.mu.Lock()
	expired, cause := c.expired, c.cause
	c.mu.Unlock()
	if expired {
		if cause != nil {
			return reason(cause)
		}
		return os.ErrDeadlineExceeded
	}
	if cause := c.errs.get(); cause != nil {
		return reason(cause)
	}
	// Xray's internal pipe, closed by an outbound that gave no reason: to
	// the caller, the link hung up.
	if errors.Is(err, io.ErrClosedPipe) {
		return io.EOF
	}
	return err
}

func (c *conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if c.expired || t.IsZero() {
		return nil
	}
	c.timer = time.AfterFunc(time.Until(t), c.expire)
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *conn) expire() {
	c.mu.Lock()
	if c.expired {
		c.mu.Unlock()
		return
	}
	c.expired = true
	c.cause = c.errs.get()
	c.mu.Unlock()
	c.Close()
}

func (c *conn) Close() error {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
	c.cancel()
	return c.Conn.Close()
}

// Xray's error chains name the package at every step, and wrap a failed dial
// in the retries around it.
var (
	pkgPrefix = regexp.MustCompile(`(^|> )([a-z0-9_]+/)+[a-z0-9_]+: `)
	retried   = regexp.MustCompile(`^failed to find an available destination > common/retry: \[(.*)\] > common/retry: all retry attempts failed$`)
)

// reason shortens Xray's error chain to its informative part, on one line:
//
//	app/proxyman/outbound: failed to process outbound traffic >
//	proxy/vless/outbound: failed to find an available destination >
//	common/retry: [dial tcp 1.2.3.4:443: connect: connection refused] >
//	common/retry: all retry attempts failed
//
// comes out as "dial tcp 1.2.3.4:443: connect: connection refused".
func reason(err error) error {
	msg := strings.ReplaceAll(err.Error(), "\n", " ")
	const lead = "failed to process outbound traffic > "
	if i := strings.Index(msg, lead); i >= 0 {
		msg = msg[i+len(lead):]
	}
	msg = strings.TrimPrefix(msg, pkgPrefix.FindString(msg))
	if m := retried.FindStringSubmatch(msg); m != nil {
		msg = m[1]
	}
	msg = pkgPrefix.ReplaceAllString(msg, "$1")
	return errors.New(msg)
}

// tracker is the system dialer under every Xray outbound. It knows which
// tunnel each socket belongs to, from the outbound tag in the dial's context,
// so closing a tunnel closes its sockets.
//
// Xray's gRPC, XHTTP and Hysteria transports keep their connections in
// process-wide pools, keyed per outbound and never emptied. Without this, a
// run would leave one idle connection behind for every such link it checked,
// and gRPC would keep reconnecting it.
type tracker struct {
	base internet.SystemDialer

	mu   sync.Mutex
	live map[string]map[net.Conn]struct{} // open tunnels, by tag, with their sockets
}

var errTunnelClosed = errors.New("tunnel closed")

func (t *tracker) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	tag := tagOf(ctx)
	if tag == "" {
		return t.base.Dial(ctx, src, dest, sockopt)
	}
	t.mu.Lock()
	_, ok := t.live[tag]
	t.mu.Unlock()
	if !ok {
		return nil, errTunnelClosed // a pooled transport reconnecting after its check
	}
	c, err := t.base.Dial(ctx, src, dest, sockopt)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	socks, ok := t.live[tag]
	if !ok {
		c.Close()
		return nil, errTunnelClosed
	}
	socks[c] = struct{}{}
	return c, nil
}

func (t *tracker) DestIpAddress() net.IP { return t.base.DestIpAddress() }

func (t *tracker) open(tag string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.live[tag] = make(map[net.Conn]struct{})
}

func (t *tracker) close(tag string) {
	t.mu.Lock()
	socks := t.live[tag]
	delete(t.live, tag)
	t.mu.Unlock()
	for c := range socks {
		c.Close()
	}
}

// open reports how many sockets the tracker holds, for tests.
func (t *tracker) sockets() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, s := range t.live {
		n += len(s)
	}
	return n
}

// tagOf finds the outbound a dial is made for.
func tagOf(ctx context.Context) string {
	obs := session.OutboundsFromContext(ctx)
	for i := len(obs) - 1; i >= 0; i-- {
		if obs[i] != nil && strings.HasPrefix(obs[i].Tag, "link-") {
			return obs[i].Tag
		}
	}
	return ""
}
