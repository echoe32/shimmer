package link

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const id = "b831381d-6324-4d53-ad4f-8cda48b30811"

// outbound decodes a link's Xray outbound for inspection.
func outbound(t *testing.T, l *Link) map[string]any {
	t.Helper()
	raw, err := l.Outbound("t")
	if err != nil {
		t.Fatal(err)
	}
	var ob map[string]any
	if err := json.Unmarshal(raw, &ob); err != nil {
		t.Fatal(err)
	}
	return ob
}

// at walks a decoded outbound by keys.
func at(t *testing.T, v any, keys ...string) any {
	t.Helper()
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("no %q in %v", k, v)
		}
		v = m[k]
	}
	return v
}

func mustParse(t *testing.T, s string) *Link {
	t.Helper()
	l, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%s): %v", s, err)
	}
	return l
}

func TestVLESSReality(t *testing.T) {
	l := mustParse(t, "vless://"+id+"@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=KEY&sid=ab12&spx=%2F&type=tcp&headerType=none#My%20Server")
	if l.Protocol != VLESS || l.Host != "1.2.3.4" || l.Port != 443 || l.Name != "My Server" {
		t.Errorf("got %+v", l)
	}
	if l.Transport != "raw" || l.Security != "reality" {
		t.Errorf("transport %q security %q, want raw and reality", l.Transport, l.Security)
	}
	ob := outbound(t, l)
	if at(t, ob, "protocol") != "vless" || at(t, ob, "tag") != "t" {
		t.Errorf("outbound %v", ob)
	}
	if at(t, ob, "settings", "id") != id || at(t, ob, "settings", "flow") != "xtls-rprx-vision" || at(t, ob, "settings", "encryption") != "none" {
		t.Errorf("settings %v", at(t, ob, "settings"))
	}
	r := at(t, ob, "streamSettings", "realitySettings")
	if at(t, r, "publicKey") != "KEY" || at(t, r, "shortId") != "ab12" || at(t, r, "serverName") != "www.example.com" || at(t, r, "spiderX") != "/" {
		t.Errorf("reality %v", r)
	}
}

func TestVLESSWebSocketTLS(t *testing.T) {
	l := mustParse(t, "vless://"+id+"@cdn.example.com:443?type=ws&path=%2Fws%3Fed%3D2048&host=real.example.com&security=tls&alpn=h2,http/1.1&fp=chrome")
	ob := outbound(t, l)
	ws := at(t, ob, "streamSettings", "wsSettings")
	if at(t, ws, "path") != "/ws?ed=2048" || at(t, ws, "host") != "real.example.com" {
		t.Errorf("ws %v", ws)
	}
	tls := at(t, ob, "streamSettings", "tlsSettings")
	// No sni: the Host header is the name a client presents.
	if at(t, tls, "serverName") != "real.example.com" || at(t, tls, "fingerprint") != "chrome" {
		t.Errorf("tls %v", tls)
	}
	if alpn, _ := at(t, tls, "alpn").([]any); len(alpn) != 2 {
		t.Errorf("alpn %v", at(t, tls, "alpn"))
	}
}

func TestTransports(t *testing.T) {
	for _, c := range []struct {
		query, network, settings string
	}{
		{"type=grpc&serviceName=svc&mode=multi", "grpc", "grpcSettings"},
		{"type=httpupgrade&path=/up", "httpupgrade", "httpupgradeSettings"},
		{"type=xhttp&path=/x&mode=stream-one", "xhttp", "xhttpSettings"},
		{"type=splithttp&path=/x", "xhttp", "xhttpSettings"},
		{"type=tcp&headerType=http&path=/a&host=h.example.com", "raw", "rawSettings"},
	} {
		l := mustParse(t, "vless://"+id+"@1.2.3.4:443?security=none&"+c.query)
		ob := outbound(t, l)
		if got := at(t, ob, "streamSettings", "network"); got != c.network {
			t.Errorf("%s: network %v, want %s", c.query, got, c.network)
		}
		if at(t, ob, "streamSettings", c.settings) == nil {
			t.Errorf("%s: no %s in %v", c.query, c.settings, at(t, ob, "streamSettings"))
		}
	}
	grpc := at(t, outbound(t, mustParse(t, "vless://"+id+"@1.2.3.4:443?type=grpc&serviceName=svc&mode=multi")), "streamSettings", "grpcSettings")
	if at(t, grpc, "serviceName") != "svc" || at(t, grpc, "multiMode") != true {
		t.Errorf("grpc %v", grpc)
	}
}

func TestXHTTPExtra(t *testing.T) {
	for _, extra := range []string{
		`%7B%22xPaddingBytes%22%3A%22100-1000%22%7D`,
		`{"xPaddingBytes":"100-1000"}`,
		`{"xPaddingBytes":+"100-1000"}`, // form-encoded, '+' for a space
	} {
		l := mustParse(t, "vless://"+id+"@1.2.3.4:443?type=xhttp&extra="+extra)
		x := at(t, outbound(t, l), "streamSettings", "xhttpSettings", "extra", "xPaddingBytes")
		if x != "100-1000" {
			t.Errorf("extra %s: got %v", extra, x)
		}
	}
}

// Xray builds an XHTTP link's request URL from its Host header, else its SNI,
// and the query part of its path, and crashes the process when that does not
// parse. Such a link must be refused here instead.
func TestXHTTPRequestURL(t *testing.T) {
	base := "vless://" + id + "@1.2.3.4:443?type=xhttp&mode=stream-one&"
	for _, q := range []string{
		"security=tls&path=/de&sni=de.example.online@oliver", // as found in a real list
		"security=tls&host=a%20b",                            // Host header with a space
		"security=reality&pbk=KEY&sni=a@b",                   // REALITY's server name
		"security=none&path=/x%3Fa%0Ab",                      // control byte in the query
	} {
		_, err := Parse(base + q)
		if err == nil || !strings.Contains(err.Error(), "xhttp request URL") {
			t.Errorf("%s: err %v, want the request URL refused", q, err)
		}
	}
	for _, q := range []string{
		"security=tls&path=/x?ed=2048&sni=a.example.com",
		"security=tls&host=ok.example.com&sni=a@b", // the Host header wins, so the SNI is not in the URL
		"security=none", // no name at all: Xray uses the server's address
	} {
		mustParse(t, base+q)
	}
	// Only XHTTP puts the name in a URL; elsewhere a bad SNI fails the TLS
	// handshake, as it would in a client.
	mustParse(t, "vless://"+id+"@1.2.3.4:443?type=ws&security=tls&sni=a@b")
}

func TestTrojanDefaultsToTLS(t *testing.T) {
	l := mustParse(t, "trojan://pass%40word@example.com:443#t")
	if l.Security != "tls" {
		t.Errorf("security %q, want tls", l.Security)
	}
	ob := outbound(t, l)
	if at(t, ob, "settings", "password") != "pass@word" {
		t.Errorf("password %v", at(t, ob, "settings", "password"))
	}
	if at(t, ob, "streamSettings", "tlsSettings", "serverName") != "example.com" {
		t.Errorf("sni %v", at(t, ob, "streamSettings", "tlsSettings"))
	}
	if l := mustParse(t, "trojan://p@1.2.3.4:80?security=none"); l.Security != "none" {
		t.Errorf("explicit none became %q", l.Security)
	}
}

func TestVMessJSON(t *testing.T) {
	// Numbers where other lists write strings, and a vmess "type" that is a
	// header type.
	body := `{"v":"2","ps":"name one","add":"1.2.3.4","port":8443,"id":"` + id + `","aid":0,"scy":"","net":"tcp","type":"http","host":"h.example.com","path":"/p","tls":"tls","sni":"s.example.com"}`
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		l := mustParse(t, "vmess://"+enc.EncodeToString([]byte(body)))
		if l.Host != "1.2.3.4" || l.Port != 8443 || l.Name != "name one" || l.Security != "tls" {
			t.Errorf("got %+v", l)
		}
		ob := outbound(t, l)
		if at(t, ob, "settings", "security") != "auto" {
			t.Errorf("cipher %v, want auto", at(t, ob, "settings", "security"))
		}
		if at(t, ob, "streamSettings", "rawSettings", "header", "type") != "http" {
			t.Errorf("header %v", at(t, ob, "streamSettings"))
		}
		if at(t, ob, "streamSettings", "tlsSettings", "serverName") != "s.example.com" {
			t.Errorf("sni %v", at(t, ob, "streamSettings", "tlsSettings"))
		}
	}
}

func TestVMessGRPCTypeIsMode(t *testing.T) {
	body := `{"add":"1.2.3.4","port":"443","id":"` + id + `","net":"grpc","type":"multi","path":"svc","tls":""}`
	ob := outbound(t, mustParse(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(body))))
	g := at(t, ob, "streamSettings", "grpcSettings")
	if at(t, g, "serviceName") != "svc" || at(t, g, "multiMode") != true {
		t.Errorf("grpc %v", g)
	}
}

// "none" in a vmess "type" is the header type's default, which generators
// write whatever the transport. Taken as an XHTTP mode, Xray refused to build
// the outbound, and the link was recorded dead.
func TestVMessXHTTPTypeNoneIsNoMode(t *testing.T) {
	for typ, want := range map[string]any{"none": nil, "None": nil, "": nil, "packet-up": "packet-up"} {
		body := `{"add":"1.2.3.4","port":"443","id":"` + id + `","net":"xhttp","type":"` + typ + `","path":"/x","tls":"tls","sni":"a.example.com"}`
		ob := outbound(t, mustParse(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(body))))
		if got := at(t, ob, "streamSettings", "xhttpSettings", "mode"); got != want {
			t.Errorf("type %q: mode %v, want %v", typ, got, want)
		}
	}
}

func TestVMessURI(t *testing.T) {
	l := mustParse(t, "vmess://"+id+"@1.2.3.4:22324?encryption=auto&security=none&type=ws&path=/v#🛞74@channel")
	if l.Name != "🛞74@channel" || l.Transport != "ws" {
		t.Errorf("got %+v", l)
	}
}

func TestShadowsocksForms(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:p@ss"))
	legacy := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw@5.6.7.8:8388"))
	for _, c := range []struct {
		link, method, password, host string
	}{
		{"ss://" + userinfo + "@1.2.3.4:8388#n", "chacha20-ietf-poly1305", "p@ss", "1.2.3.4"},
		{"ss://" + userinfo + "@1.2.3.4:8388/?#n", "chacha20-ietf-poly1305", "p@ss", "1.2.3.4"},
		{"ss://2022-blake3-aes-128-gcm:a2V5%3D@1.2.3.4:8388", "2022-blake3-aes-128-gcm", "a2V5=", "1.2.3.4"},
		{"ss://" + legacy + "#old", "aes-256-gcm", "pw", "5.6.7.8"},
		// An '@' in the query is not the one that ends the userinfo.
		{"ss://" + userinfo + "@1.2.3.4:8388?note=@channel#n", "chacha20-ietf-poly1305", "p@ss", "1.2.3.4"},
		{"ss://" + userinfo + "@1.2.3.4:8388/?note=@a@b", "chacha20-ietf-poly1305", "p@ss", "1.2.3.4"},
	} {
		l := mustParse(t, c.link)
		ob := outbound(t, l)
		if at(t, ob, "protocol") != "shadowsocks" || at(t, ob, "settings", "method") != c.method ||
			at(t, ob, "settings", "password") != c.password || l.Host != c.host {
			t.Errorf("%s: got %v", c.link, ob)
		}
	}
}

func TestHysteria2(t *testing.T) {
	l := mustParse(t, "hy2://auth@1.2.3.4:443/?insecure=1&sni=www.bing.com&obfs=salamander&obfs-password=secret&pinSHA256=AB:CD#hy")
	if l.Protocol != Hysteria2 || !l.Insecure || !l.UDP() {
		t.Errorf("got %+v, UDP %t", l, l.UDP())
	}
	ob := outbound(t, l)
	if at(t, ob, "protocol") != "hysteria" || at(t, ob, "streamSettings", "hysteriaSettings", "auth") != "auth" {
		t.Errorf("outbound %v", ob)
	}
	tls := at(t, ob, "streamSettings", "tlsSettings")
	if at(t, tls, "serverName") != "www.bing.com" || at(t, tls, "pinnedPeerCertSha256") != "abcd" {
		t.Errorf("tls %v", tls)
	}
	masks, _ := at(t, ob, "streamSettings", "finalmask", "udp").([]any)
	if len(masks) != 1 || at(t, masks[0], "type") != "salamander" || at(t, masks[0], "settings", "password") != "secret" {
		t.Errorf("finalmask %v", masks)
	}
	if l := mustParse(t, "hysteria2://a@1.2.3.4:443"); l.Protocol != Hysteria2 {
		t.Errorf("hysteria2:// scheme: %+v", l)
	}
}

func TestUDP(t *testing.T) {
	for link, want := range map[string]bool{
		"vless://" + id + "@1.2.3.4:443?type=kcp":                           true,
		"vless://" + id + "@1.2.3.4:443?type=xhttp&security=tls&alpn=h3":    true,
		"vless://" + id + "@1.2.3.4:443?type=xhttp&security=tls&alpn=h3,h2": false,
		"vless://" + id + "@1.2.3.4:443?type=ws":                            false,
	} {
		if got := mustParse(t, link).UDP(); got != want {
			t.Errorf("%s: UDP %t, want %t", link, got, want)
		}
	}
}

// Insecure is carried beside the outbound, never in it: Xray refuses the
// setting in JSON.
func TestInsecure(t *testing.T) {
	for _, q := range []string{"allowInsecure=1", "insecure=1", "allowinsecure=true"} {
		l := mustParse(t, "vless://"+id+"@1.2.3.4:443?security=tls&"+q)
		if !l.Insecure {
			t.Errorf("%s: not insecure", q)
		}
		raw, _ := l.Outbound("t")
		if strings.Contains(strings.ToLower(string(raw)), "insecure") {
			t.Errorf("%s: outbound carries it: %s", q, raw)
		}
	}
	if mustParse(t, "vless://"+id+"@1.2.3.4:443?security=tls&allowInsecure=0").Insecure {
		t.Error("allowInsecure=0 read as insecure")
	}
}

// Links that differ only in their names and parameter spellings are one
// link; any real difference makes another.
func TestKey(t *testing.T) {
	a := mustParse(t, "vless://"+id+"@1.2.3.4:443?security=tls&sni=a.example.com&type=ws&path=/p#one")
	b := mustParse(t, "VLESS://"+id+"@1.2.3.4:443?type=ws&path=%2Fp&SNI=a.example.com&security=tls#two")
	c := mustParse(t, "vless://"+id+"@1.2.3.4:443?security=tls&sni=a.example.com&type=ws&path=/q#one")
	d := mustParse(t, "vless://"+id+"@1.2.3.4:443?security=tls&sni=a.example.com&type=ws&path=/p&allowInsecure=1#one")
	if a.Key() != b.Key() || a.ID() != b.ID() {
		t.Errorf("same link, different keys:\n%s\n%s", a.Key(), b.Key())
	}
	if a.Key() == c.Key() || a.Key() == d.Key() {
		t.Error("different links share a key")
	}
	if len(a.ID()) != 32 {
		t.Errorf("ID %q, want 32 hex digits", a.ID())
	}
}

func TestRefused(t *testing.T) {
	for _, s := range []string{
		"vless://1.2.3.4:443",                                                                                     // no id
		"vless://" + id + "@1.2.3.4:443?type=h2",                                                                  // transport Xray removed
		"vless://" + id + "@1.2.3.4:443?type=wsoliver",                                                            // no such transport
		"vless://" + id + "@1.2.3.4:443?security=reality",                                                         // reality with no key
		"vless://" + id + "@1.2.3.4:443?type=kcp&seed=abc",                                                        // mKCP seed, removed
		"vless://" + id + "@1.2.3.4:443?security=magic",                                                           // no such security
		"vless://" + id + "@1.2.3.4:0",                                                                            // port zero
		"vless://" + id + "@bad host:443",                                                                         // not a host
		"vless://" + id + "@1.2.3.4:443?type=xhttp&extra={",                                                       // extra not JSON
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-cfb:pw")) + "@1.2.3.4:8388",                   // stream cipher
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@1.2.3.4:8388?plugin=obfs-local", // plugin
		"ss://@Net2ray@1.2.3.4:17396?security=none",                                                               // a vless link labelled ss
		"vmess://bm90IGpzb24",                                                                                     // base64, not JSON
		"hy2://1.2.3.4:443/?sni=x",                                                                                // no auth
		"hy2://a@1.2.3.4:443/?obfs=salamander",                                                                    // obfs with no password
		"ssr://abc",                                                                                               // not a scheme we read
	} {
		if l, err := Parse(s); err == nil {
			t.Errorf("Parse(%s) = %+v, want an error", s, l)
		}
	}
}

func TestIs(t *testing.T) {
	for s, want := range map[string]bool{
		"vless://x":           true,
		"VMESS://x":           true,
		"hy2://x":             true,
		"ss://x":              true,
		"socks5://1.2.3.4:80": false,
		"1.2.3.4:80":          false,
		"ssr://x":             false,
	} {
		if Is(s) != want {
			t.Errorf("Is(%s) = %t, want %t", s, !want, want)
		}
	}
}
