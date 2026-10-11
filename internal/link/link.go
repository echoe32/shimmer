// Package link reads the share links V2Ray-family clients pass around
// (vless://, vmess://, trojan://, ss://, hysteria2://) and turns each one into
// an Xray outbound.
//
// Subscription lists are untidy: parameters appear under several spellings,
// values are half-escaped, and names carry emoji and spaces. The parser takes
// what a client such as v2rayN would take, and refuses a link only when no
// client could connect with it.
package link

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// The protocols a link can name, as recorded in results.
const (
	VLESS       = "vless"
	VMess       = "vmess"
	Trojan      = "trojan"
	Shadowsocks = "ss"
	Hysteria2   = "hysteria2"
)

// Protocols is every protocol a link can name.
func Protocols() []string { return []string{VLESS, VMess, Trojan, Shadowsocks, Hysteria2} }

// schemes maps each scheme this package reads to the protocol it names.
var schemes = map[string]string{
	"vless":     VLESS,
	"vmess":     VMess,
	"trojan":    Trojan,
	"ss":        Shadowsocks,
	"hysteria2": Hysteria2,
	"hy2":       Hysteria2,
}

// Link is one parsed share link.
type Link struct {
	Protocol  string // one of Protocols
	Host      string // the server, as the link names it
	Port      uint16
	Transport string // raw, ws, grpc, httpupgrade, xhttp, kcp or hysteria
	Security  string // none, tls or reality
	Name      string // the link's label: its fragment, or "ps" in vmess
	Raw       string // the link as it was read, without surrounding space

	// Insecure asks for the server's certificate not to be verified. Xray
	// refuses the setting in its JSON form, so the engine applies it after
	// the outbound is built.
	Insecure bool

	outbound map[string]any // Xray outbound JSON, without a tag
}

// Is reports whether s starts with a scheme this package reads.
func Is(s string) bool {
	scheme, _, ok := strings.Cut(s, "://")
	if !ok {
		return false
	}
	_, known := schemes[strings.ToLower(scheme)]
	return known
}

// Parse reads one share link.
func Parse(s string) (*Link, error) {
	s = strings.TrimSpace(s)
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return nil, errors.New("not a share link")
	}
	proto, known := schemes[strings.ToLower(scheme)]
	if !known {
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
	var (
		l   *Link
		err error
	)
	switch proto {
	case VLESS, Trojan:
		l, err = parseURI(proto, rest)
	case VMess:
		l, err = parseVMess(rest)
	case Shadowsocks:
		l, err = parseShadowsocks(rest)
	case Hysteria2:
		l, err = parseHysteria2(rest)
	}
	if err != nil {
		return nil, fmt.Errorf("%s link: %w", proto, err)
	}
	l.Raw = s
	return l, nil
}

// Addr renders the server as a dialable "host:port".
func (l *Link) Addr() string { return net.JoinHostPort(l.Host, strconv.Itoa(int(l.Port))) }

// UDP reports whether the link's transport runs over UDP, where a TCP connect
// to the server proves nothing.
func (l *Link) UDP() bool {
	switch l.Transport {
	case "hysteria", "kcp":
		return true
	case "xhttp":
		// XHTTP over HTTP/3 is QUIC. Offered alongside h2 or http/1.1, it
		// may fall back to TCP, but the server need not listen there.
		return l.outbound != nil && alpnIsH3Only(l.outbound)
	}
	return false
}

// Outbound renders the link as an Xray outbound, tagged tag.
func (l *Link) Outbound(tag string) ([]byte, error) {
	ob := make(map[string]any, len(l.outbound)+1)
	for k, v := range l.outbound {
		ob[k] = v
	}
	ob["tag"] = tag
	return json.Marshal(ob)
}

// Key identifies the server and credentials a link describes. Two links that
// differ only in their names, or in how their parameters were spelt, share it.
func (l *Link) Key() string {
	b, err := json.Marshal(l.outbound) // map keys are sorted, so this is canonical
	if err != nil {
		return l.Raw
	}
	return fmt.Sprintf("%s|%t|%s", l.Protocol, l.Insecure, b)
}

// ID is a short, fixed-length form of Key, for a database key.
func (l *Link) ID() string {
	sum := sha256.Sum256([]byte(l.Key()))
	return hex.EncodeToString(sum[:16])
}

// uri is a link of the form scheme://user@host:port/path?query#name, taken
// apart by hand: url.Parse refuses too much of what real lists contain.
type uri struct {
	user  string
	host  string
	port  uint16
	query params
	name  string
}

func splitURI(rest string) (uri, error) {
	var u uri
	if body, frag, ok := strings.Cut(rest, "#"); ok {
		rest = body
		u.name = unescape(frag)
	}
	var rawQuery string
	if body, q, ok := strings.Cut(rest, "?"); ok {
		rest, rawQuery = body, q
	}
	// A path before the query ("host:port/?sni=...") carries nothing.
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	i := strings.LastIndexByte(rest, '@')
	if i < 0 {
		return u, errors.New("no user part")
	}
	u.user = unescape(rest[:i])
	host, port, err := hostPort(rest[i+1:])
	if err != nil {
		return u, err
	}
	u.host, u.port = host, port
	u.query = parseQuery(rawQuery)
	return u, nil
}

// hostPort reads "host:port" or "[v6]:port".
func hostPort(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("bad address %q", truncate(s))
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("bad port %q", truncate(portStr))
	}
	if !validHost(host) {
		return "", 0, fmt.Errorf("bad host %q", truncate(host))
	}
	return host, uint16(port), nil
}

// validHost accepts an IP address or a DNS name.
func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

// params is a query string with its keys folded to lower case: lists spell
// "serviceName" and "servicename", "allowInsecure" and "allowinsecure".
type params map[string]string

func parseQuery(q string) params {
	p := make(params)
	for pair := range strings.SplitSeq(q, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		k = strings.ToLower(unescape(k))
		if _, dup := p[k]; dup { // the first spelling wins
			continue
		}
		p[k] = unescape(v)
	}
	return p
}

// get returns the first of keys that is set to something.
func (p params) get(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(p[k]); v != "" {
			return v
		}
	}
	return ""
}

func (p params) flag(keys ...string) bool {
	switch strings.ToLower(p.get(keys...)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// unescape percent-decodes s, leaving '+' alone: base64 values such as an ECH
// config carry it literally. What does not decode is kept as written.
func unescape(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

func parseURI(proto, rest string) (*Link, error) {
	u, err := splitURI(rest)
	if err != nil {
		return nil, err
	}
	if u.user == "" {
		return nil, errors.New("no id or password")
	}
	l := &Link{Protocol: proto, Host: u.host, Port: u.port, Name: u.name}
	settings := map[string]any{"address": u.host, "port": u.port}
	switch proto {
	case VLESS:
		settings["id"] = u.user
		enc := u.query.get("encryption")
		if enc == "" {
			enc = "none"
		}
		settings["encryption"] = enc
		if flow := u.query.get("flow"); flow != "" {
			settings["flow"] = flow
		}
	case Trojan:
		settings["password"] = u.user
		// Trojan is TLS by design: a link that names no security means it.
		if _, named := u.query["security"]; !named {
			u.query["security"] = "tls"
		}
	}
	stream, err := streamFrom(l, u.host, u.query)
	if err != nil {
		return nil, err
	}
	l.outbound = map[string]any{
		"protocol":       outboundProtocol(proto),
		"settings":       settings,
		"streamSettings": stream,
	}
	return l, nil
}

// outboundProtocol is Xray's name for a link protocol.
func outboundProtocol(proto string) string {
	switch proto {
	case Shadowsocks:
		return "shadowsocks"
	case Hysteria2:
		return "hysteria"
	}
	return proto
}

// streamFrom builds the transport and security of a vless, trojan or vmess
// link from its parameters, and records both on l.
func streamFrom(l *Link, host string, q params) (map[string]any, error) {
	stream := map[string]any{}
	network := strings.ToLower(q.get("type", "net", "network"))
	path := q.get("path")
	hostHeader := q.get("host")
	switch network {
	case "", "tcp", "raw":
		network = "raw"
		switch header := strings.ToLower(q.get("headertype", "header")); header {
		case "", "none":
		case "http":
			req := map[string]any{"path": []string{orSlash(path)}}
			if hostHeader != "" {
				req["headers"] = map[string]any{"Host": splitList(hostHeader)}
			}
			stream["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		default:
			return nil, fmt.Errorf("unsupported tcp header %q", truncate(header))
		}
	case "ws", "websocket":
		network = "ws"
		stream["wsSettings"] = pathHost(path, hostHeader)
	case "httpupgrade":
		stream["httpupgradeSettings"] = pathHost(path, hostHeader)
	case "grpc", "gun":
		network = "grpc"
		g := map[string]any{}
		if name := q.get("servicename", "path"); name != "" {
			g["serviceName"] = name
		}
		if a := q.get("authority"); a != "" {
			g["authority"] = a
		}
		if strings.EqualFold(q.get("mode"), "multi") {
			g["multiMode"] = true
		}
		stream["grpcSettings"] = g
	case "xhttp", "splithttp":
		network = "xhttp"
		x := pathHost(path, hostHeader)
		if mode := q.get("mode"); mode != "" {
			x["mode"] = mode
		}
		if extra := q.get("extra"); extra != "" {
			var v map[string]any
			if err := json.Unmarshal([]byte(extra), &v); err != nil {
				// Form-encoded by some panels, with '+' for each space.
				if json.Unmarshal([]byte(strings.ReplaceAll(extra, "+", " ")), &v) != nil {
					return nil, fmt.Errorf("xhttp extra is not JSON: %w", err)
				}
			}
			x["extra"] = v
		}
		stream["xhttpSettings"] = x
	case "kcp", "mkcp":
		network = "kcp"
		if q.get("seed") != "" {
			return nil, errors.New("mkcp seed is no longer supported by Xray")
		}
		if h := strings.ToLower(q.get("headertype")); h != "" && h != "none" {
			return nil, fmt.Errorf("mkcp header %q is no longer supported by Xray", truncate(h))
		}
	case "http", "h2", "h3", "quic":
		return nil, fmt.Errorf("the %s transport is no longer supported by Xray", network)
	default:
		return nil, fmt.Errorf("unknown transport %q", truncate(network))
	}
	stream["network"] = network
	l.Transport = network

	security := strings.ToLower(q.get("security", "tls"))
	switch security {
	case "", "none", "false", "0":
		security = "none"
	case "tls", "true", "1", "xtls":
		security = "tls"
		stream["tlsSettings"] = tlsSettings(l, host, hostHeader, q)
	case "reality":
		pbk := q.get("pbk", "publickey", "password")
		if pbk == "" {
			return nil, errors.New("reality without a public key (pbk)")
		}
		r := map[string]any{
			"publicKey":   pbk,
			"fingerprint": orDefault(strings.ToLower(q.get("fp", "fingerprint")), "chrome"),
		}
		if sni := q.get("sni", "servername", "peer"); sni != "" {
			r["serverName"] = sni
		}
		setIf(r, "shortId", q.get("sid", "shortid"))
		setIf(r, "spiderX", q.get("spx", "spiderx"))
		setIf(r, "mldsa65Verify", q.get("pqv"))
		stream["realitySettings"] = r
	default:
		return nil, fmt.Errorf("unknown security %q", truncate(security))
	}
	stream["security"] = security
	l.Security = security
	if network == "xhttp" {
		if err := checkXHTTP(stream); err != nil {
			return nil, err
		}
	}
	return stream, nil
}

// checkXHTTP refuses an XHTTP link whose request URL does not parse. Xray
// builds that URL from the Host header (else the SNI) and the query part of
// the path, ignores the error when it does not parse, and dereferences the
// nil request in a goroutine of its own. One such link, with an SNI of
// "name@channel", crashed the whole run, out of reach of any recover here,
// and every -resume after it.
func checkXHTTP(stream map[string]any) error {
	x, _ := stream["xhttpSettings"].(map[string]any)
	host, _ := x["host"].(string)
	for _, key := range []string{"tlsSettings", "realitySettings"} {
		if host != "" {
			break
		}
		s, _ := stream[key].(map[string]any)
		host, _ = s["serverName"].(string)
	}
	path, _ := x["path"].(string)
	_, query, _ := strings.Cut(path, "?")
	// With neither, Xray uses the server's address, which is always valid.
	u := url.URL{Scheme: "https", Host: orDefault(host, "server"), Path: "/", RawQuery: query}
	if _, err := url.Parse(u.String()); err != nil {
		return fmt.Errorf("xhttp request URL does not parse: %w", err)
	}
	return nil
}

// tlsSettings reads the TLS parameters shared by every protocol.
func tlsSettings(l *Link, host, hostHeader string, q params) map[string]any {
	t := map[string]any{}
	sni := q.get("sni", "servername", "peer")
	if sni == "" {
		// Clients fall back to the Host header, then to the server's own
		// name. An IP address makes no SNI at all.
		sni = firstOf(splitList(hostHeader))
		if sni == "" {
			if _, err := netip.ParseAddr(host); err != nil {
				sni = host
			}
		}
	}
	setIf(t, "serverName", sni)
	if alpn := splitList(q.get("alpn")); len(alpn) > 0 {
		t["alpn"] = alpn
	}
	setIf(t, "fingerprint", strings.ToLower(q.get("fp", "fingerprint")))
	setIf(t, "pinnedPeerCertSha256", q.get("pcs", "pinsha256"))
	setIf(t, "verifyPeerCertByName", q.get("vcn"))
	setIf(t, "echConfigList", q.get("ech"))
	l.Insecure = q.flag("allowinsecure", "insecure", "skip-cert-verify")
	return t
}

func pathHost(path, host string) map[string]any {
	m := map[string]any{"path": orSlash(path)}
	setIf(m, "host", firstOf(splitList(host)))
	return m
}

// alpnIsH3Only reports whether an outbound offers only HTTP/3.
func alpnIsH3Only(ob map[string]any) bool {
	stream, _ := ob["streamSettings"].(map[string]any)
	tls, _ := stream["tlsSettings"].(map[string]any)
	alpn, _ := tls["alpn"].([]string)
	return len(alpn) == 1 && alpn[0] == "h3"
}

// vmessJSON is the base64 JSON body of a vmess link, as v2rayN writes it.
// Several fields are numbers in some lists and strings in others.
type vmessJSON struct {
	PS            flex `json:"ps"`
	Add           flex `json:"add"`
	Port          flex `json:"port"`
	ID            flex `json:"id"`
	Scy           flex `json:"scy"`
	Net           flex `json:"net"`
	Type          flex `json:"type"`
	Host          flex `json:"host"`
	Path          flex `json:"path"`
	TLS           flex `json:"tls"`
	SNI           flex `json:"sni"`
	ALPN          flex `json:"alpn"`
	FP            flex `json:"fp"`
	Insecure      flex `json:"insecure"`
	AllowInsecure flex `json:"allowInsecure"`
	Mode          flex `json:"mode"`
	ServiceName   flex `json:"serviceName"`
	Authority     flex `json:"authority"`
	PBK           flex `json:"pbk"`
	SID           flex `json:"sid"`
	SPX           flex `json:"spx"`
}

// flex is a JSON value read as text, whatever its type.
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flex(s)
		return nil
	}
	*f = flex(strings.Trim(string(b), `"`))
	if string(b) == "null" {
		*f = ""
	}
	return nil
}

func parseVMess(rest string) (*Link, error) {
	body, frag, _ := strings.Cut(rest, "#")
	raw, err := decodeBase64(body)
	if err != nil {
		// The other common form: vmess://uuid@host:port?type=ws&...
		if strings.Contains(rest, "@") {
			return parseVMessURI(rest)
		}
		return nil, errors.New("body is neither base64 nor uuid@host:port")
	}
	var v vmessJSON
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("body is not JSON: %w", err)
	}
	host, port, err := hostPort(net.JoinHostPort(strings.TrimSpace(string(v.Add)), strings.TrimSpace(string(v.Port))))
	if err != nil {
		return nil, err
	}
	if v.ID == "" {
		return nil, errors.New("no id")
	}
	name := string(v.PS)
	if name == "" && frag != "" {
		name = unescape(frag)
	}
	q := params{
		"type":          string(v.Net),
		"headertype":    string(v.Type),
		"host":          string(v.Host),
		"path":          string(v.Path),
		"security":      string(v.TLS),
		"sni":           string(v.SNI),
		"alpn":          string(v.ALPN),
		"fp":            string(v.FP),
		"insecure":      string(v.Insecure),
		"allowinsecure": string(v.AllowInsecure),
		"servicename":   string(v.ServiceName),
		"authority":     string(v.Authority),
		"pbk":           string(v.PBK),
		"sid":           string(v.SID),
		"spx":           string(v.SPX),
	}
	// In vmess JSON, "type" is the header type for raw and kcp, and the
	// mode for grpc and xhttp.
	switch strings.ToLower(string(v.Net)) {
	case "grpc", "gun", "xhttp", "splithttp":
		q["headertype"] = ""
		// "none" is the header type's default, which generators write
		// whatever the transport. As an XHTTP mode, Xray refuses it.
		mode := string(v.Type)
		if strings.EqualFold(mode, "none") {
			mode = ""
		}
		q["mode"] = orDefault(string(v.Mode), mode)
		if strings.EqualFold(string(v.Net), "grpc") && q["servicename"] == "" {
			q["servicename"] = string(v.Path)
		}
	}
	return vmessLink(host, port, name, string(v.ID), string(v.Scy), q)
}

func parseVMessURI(rest string) (*Link, error) {
	u, err := splitURI(rest)
	if err != nil {
		return nil, err
	}
	if u.user == "" {
		return nil, errors.New("no id")
	}
	return vmessLink(u.host, u.port, u.name, u.user, u.query.get("encryption", "scy"), u.query)
}

func vmessLink(host string, port uint16, name, id, cipher string, q params) (*Link, error) {
	l := &Link{Protocol: VMess, Host: host, Port: port, Name: name}
	cipher = strings.ToLower(strings.TrimSpace(cipher))
	if cipher == "" {
		cipher = "auto"
	}
	stream, err := streamFrom(l, host, q)
	if err != nil {
		return nil, err
	}
	l.outbound = map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"address":  host,
			"port":     port,
			"id":       strings.TrimSpace(id),
			"security": cipher,
		},
		"streamSettings": stream,
	}
	return l, nil
}

// ssCiphers are the Shadowsocks methods Xray implements. The stream ciphers
// of the original protocol (aes-256-cfb, rc4-md5, ...) are not among them.
var ssCiphers = map[string]bool{
	"aes-128-gcm":                   true,
	"aes-256-gcm":                   true,
	"chacha20-poly1305":             true,
	"chacha20-ietf-poly1305":        true,
	"xchacha20-poly1305":            true,
	"xchacha20-ietf-poly1305":       true,
	"none":                          true,
	"plain":                         true,
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
}

func parseShadowsocks(rest string) (*Link, error) {
	body, frag, _ := strings.Cut(rest, "#")
	name := unescape(frag)

	// The query comes off first: lists add notes such as "?note=@channel",
	// and the '@' in one was taken for the one that ends the userinfo.
	var userinfo, addr, rawQuery string
	if b, q, ok := strings.Cut(body, "?"); ok {
		body, rawQuery = b, q
	}
	if i := strings.LastIndexByte(body, '@'); i >= 0 {
		// SIP002: ss://userinfo@host:port/?plugin=...
		userinfo = body[:i]
		addr = strings.TrimSuffix(body[i+1:], "/")
		if dec, err := decodeBase64(unescape(userinfo)); err == nil && strings.Contains(string(dec), ":") {
			userinfo = string(dec)
		} else {
			userinfo = unescape(userinfo) // plain "method:password", as AEAD-2022 links write it
		}
	} else {
		// The original form: ss://base64(method:password@host:port)
		dec, err := decodeBase64(strings.TrimSuffix(body, "/"))
		if err != nil {
			return nil, errors.New("body is neither base64 nor userinfo@host:port")
		}
		s := string(dec)
		i := strings.LastIndexByte(s, '@')
		if i < 0 {
			return nil, errors.New("no server in the decoded body")
		}
		userinfo, addr = s[:i], s[i+1:]
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok || password == "" {
		return nil, errors.New("no method:password")
	}
	method = strings.ToLower(strings.TrimSpace(method))
	if !ssCiphers[method] {
		return nil, fmt.Errorf("cipher %q is not supported by Xray", truncate(method))
	}
	if q := parseQuery(rawQuery); q.get("plugin") != "" {
		return nil, fmt.Errorf("plugin %q is not supported by Xray", truncate(q.get("plugin")))
	}
	host, port, err := hostPort(addr)
	if err != nil {
		return nil, err
	}
	l := &Link{Protocol: Shadowsocks, Host: host, Port: port, Name: name, Transport: "raw", Security: "none"}
	l.outbound = map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{
			"address":  host,
			"port":     port,
			"method":   method,
			"password": password,
		},
	}
	return l, nil
}

func parseHysteria2(rest string) (*Link, error) {
	u, err := splitURI(rest)
	if err != nil {
		return nil, err
	}
	l := &Link{Protocol: Hysteria2, Host: u.host, Port: u.port, Name: u.name, Transport: "hysteria", Security: "tls"}
	q := u.query
	t := tlsSettings(l, u.host, "", q)
	if _, ok := t["alpn"]; !ok {
		t["alpn"] = []string{"h3"}
	}
	if pin, ok := t["pinnedPeerCertSha256"].(string); ok {
		// Hysteria writes the hash with colons; Xray wants bare hex.
		t["pinnedPeerCertSha256"] = strings.ToLower(strings.ReplaceAll(pin, ":", ""))
	}
	stream := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      t,
		"hysteriaSettings": map[string]any{"version": 2, "auth": u.user},
	}
	switch obfs := strings.ToLower(q.get("obfs")); obfs {
	case "", "none", "plain":
	case "salamander":
		pw := q.get("obfs-password", "obfs_password", "obfspassword")
		if pw == "" {
			return nil, errors.New("salamander obfuscation without a password")
		}
		stream["finalmask"] = map[string]any{
			"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": pw}}},
		}
	default:
		return nil, fmt.Errorf("unsupported obfuscation %q", truncate(obfs))
	}
	l.outbound = map[string]any{
		"protocol":       "hysteria",
		"settings":       map[string]any{"version": 2, "address": u.host, "port": u.port},
		"streamSettings": stream,
	}
	return l, nil
}

// decodeBase64 reads standard or URL-safe base64, padded or not, as lists use
// all four.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func firstOf(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

func orSlash(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func setIf(m map[string]any, key, v string) {
	if v != "" {
		m[key] = v
	}
}

func truncate(s string) string {
	if len(s) <= 48 {
		return s
	}
	return s[:48] + "..."
}
