# Shimmer: proxy checker

`shimmer` reads a list of proxies, works out which ones really forward traffic,
measures how fast each one is, and writes one result per proxy as JSONL or
CSV. It can also keep every result in a SQLite database, with live and dead
proxies in separate tables, across runs. It can report the address a proxy's
traffic actually leaves from, and look that address up in MaxMind databases
to get a country and an ASN.

A list can hold two kinds of entry, mixed freely:

- **Classic proxies** (SOCKS5, SOCKS4, HTTP), given as an address. Their
  protocol is detected.
- **Share links** of the V2Ray family: `vless://`, `vmess://`, `trojan://`,
  `ss://` and `hysteria2://` (or `hy2://`), as subscription lists carry them.
  Each one is checked through an Xray-core built into the program. See
  [Share links](#share-links).

The list is read as a stream and results are written as a stream. A run over a
multi-million-line list holds only the probes that are in flight, not the
list itself.

## Contents

- [Quick start](#quick-start)
- [Requirements](#requirements)
- [Docker](#docker)
- [Command line](#command-line)
- [Config file](#config-file)
- [Environment and .env file](#environment-and-env-file)
- [Input](#input)
- [How one proxy is checked](#how-one-proxy-is-checked)
- [Share links](#share-links)
- [Output](#output)
- [Resuming an interrupted run](#resuming-an-interrupted-run)
- [Geo databases](#geo-databases)
- [Run behaviour and safety](#run-behaviour-and-safety)
- [Code layout](#code-layout)
- [Testing](#testing)
- [Known limitations](#known-limitations)

## Quick start

```bash
go build -o shimmer ./cmd/shimmer
```

Check a list and keep only the proxies that work:

```bash
./shimmer -i proxies.txt -o alive.jsonl -alive-only
```

Check a list, find each proxy's real exit address, and add country and ASN
from the databases in the project root. The project's `.env` file, copied
from `.env.example`, names the databases, so run it from the project root and
they are used without flags:

```bash
./shimmer -i proxies.txt -o results.jsonl -exit-ip
```

From another directory, name them yourself (see
[Where the files go](#where-the-files-go)):

```bash
shimmer -i proxies.txt -o results.jsonl -exit-ip -mmdb-city /path/to/GeoLite2-Country.mmdb -mmdb-asn /path/to/GeoLite2-ASN.mmdb
```

Keep every result in a SQLite database that later runs add to, instead of a
results file:

```bash
./shimmer -i proxies.txt -db proxies.db
```

Check a subscription list of share links, keeping the working ones. The
`link` field of each result is the link itself, ready to import into a
client:

```bash
./shimmer -i configs.txt -o alive.jsonl -alive-only -exit-ip
```

Download lists from the web instead of reading a local file:

```bash
./shimmer -lists urls.txt -o results.jsonl
```

Continue a run that was interrupted:

```bash
./shimmer -i proxies.txt -o results.jsonl -resume
```

## Requirements

- **Go 1.26** to build. The direct third-party dependencies are
  `github.com/oschwald/maxminddb-golang/v2`, `modernc.org/sqlite`, a SQLite
  written in pure Go, and `github.com/xtls/xray-core`, which checks share
  links. All three are pure Go, so the build needs no C compiler. Xray-core
  brings many dependencies of its own (gRPC, QUIC, uTLS), and makes the
  binary about 50 MB (36 MB stripped, as the Docker build does).
- **Outbound network access** to the endpoints the checks use:
  - `www.gstatic.com`, ports 80 and 443: every proxy is asked to fetch
    `/generate_204` from here.
  - `api.ipify.org`, ports 80 and 443: only with `-exit-ip`.
  - Every proxy and share-link server in the list, on its own port: TCP,
    and UDP for Hysteria2 and for XHTTP over HTTP/3.
- **MaxMind databases** are optional. Without them, `country` and `asn` stay
  empty. See [Geo databases](#geo-databases).
- **Open-file limit.** Each probe in flight holds a socket. On unix the Go
  runtime raises the soft limit towards the hard limit at startup, and the
  program runs fewer workers if the limit is still too low. On macOS the
  kernel's `kern.maxfilesperproc` counts too, whatever the soft limit says.

## Docker

The image holds only the static `shimmer` binary and CA certificates (about 36 MB,
built `FROM scratch`). It runs as an unprivileged user (uid 65532) with
`/data` as the working directory, so relative paths in flags and the config
file resolve there.

```bash
docker build -t shimmer .
```

Mount the directory holding the lists, results, `.mmdb` files and `.env` at
`/data`. Run from the project root, the `.env` there supplies the databases:

```bash
docker run --rm -v "$PWD:/data" shimmer -i proxies.txt -o results.jsonl -exit-ip
```

Or with Compose, which mounts the project directory and sets the open-file
limit:

```bash
docker compose run --rm shimmer -i proxies.txt -db proxies.db
```

- **The geo databases are not in the image.** `.dockerignore` keeps
  everything but the Go sources out of the build, and the GeoLite2 EULA
  forbids passing the `.mmdb` files on (see
  [Licence terms](#licence-terms-to-respect)). Mount them at run time.
- **Settings:** `shimmer` reads `/data/.env`, that is, the `.env` in the mounted
  directory. `.dockerignore` keeps it out of the image too. A single run can
  add variables with `-e`, e.g. `docker run --rm -e SHIMMER_WORKERS=1000 ...`, and
  they win over the file. See
  [Environment and .env file](#environment-and-env-file).
- **Reading stdin needs `-i`** on `docker run`:
  `docker run --rm -i shimmer < proxies.txt > results.jsonl`.
- **Writing to a bind mount on Linux:** the container's user must be able to
  write to the mounted directory. Run it as yourself with
  `--user "$(id -u):$(id -g)"` (Docker Desktop on macOS maps ownership and
  needs nothing).
- **Time zone:** `checked_at` is in UTC unless `TZ` is set, e.g.
  `-e TZ=Europe/Berlin`. The zone database is built into the binary.
- **Stopping:** `docker stop` sends SIGTERM, which ends the run the way
  Ctrl-C does, with exit code 130.
- **Other platforms:** the build is pure Go, so
  `docker buildx build --platform linux/amd64,linux/arm64 .` cross-compiles
  without emulation.
- `docker run --rm shimmer` with no arguments prints the usage.

## Command line

```
shimmer -i proxies.txt [-o results.jsonl] [options]
shimmer -lists urls.txt -o results.jsonl [options]
shimmer -i proxies.txt -db results.db [options]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-i` | `-` | Proxy list file, one proxy per line. `-` reads stdin. |
| `-lists` | | File of list URLs to download, one per line. Used instead of `-i`; if both are given, `-i` is ignored. |
| `-fetch` | `4` | How many lists are downloaded at once, with `-lists`. Zero or less means 4. |
| `-o` | `-` | Results file. `-` writes to stdout. When `-db` is given and `-o` is not, no results file is written. An empty `-o ""` counts as not given. |
| `-db` | | SQLite database that keeps every result, live and dead proxies in separate tables. Kept across runs, never emptied. See [SQLite database](#sqlite-database--db). |
| `-format` | `jsonl` | `jsonl` or `csv`. |
| `-workers` | `512` | Proxies checked at the same time. Lowered automatically to fit the open-file limit. |
| `-timeout` | `10s` | Deadline for one proxy, covering every attempt made on it. |
| `-exit-ip` | off | Ask an echo service, through each live proxy, which address it sees. |
| `-skip` | | Protocols not to record, comma-separated: any of `socks5`, `socks4`, `https`, `http`, `vless`, `vmess`, `trojan`, `ss`, `hysteria2`. Proxies that speak only those, and links that name them, are left out of the results, and removed from the database. See [Skipping protocols](#skipping-protocols). |
| `-mmdb-city` | | MaxMind City or Country database, for the `country` field. |
| `-mmdb-asn` | | MaxMind ASN database, for the `asn` field. |
| `-resume` | off | Skip proxies already in the `-o` file and append the rest. |
| `-alive-only` | off | Write only the proxies that work to the `-o` file. The database still gets every result. |
| `-quiet` | off | No progress lines or summary on stderr. |
| `-config` | | JSON config file, loaded first. See [Config file](#config-file). |
| `-env` | `.env` | File of `SHIMMER_` variables, read if it exists. `-env ""` reads none. See [Environment and .env file](#environment-and-env-file). |

Every setting is a flag. An argument that is not one is refused, with the
usage, instead of being ignored along with every flag after it.

Progress is printed to stderr every 2 seconds, and a summary at the end, so
results piped from stdout stay clean:

```
read 70000, checked 51234, alive 812, 2560/s
checked 70000, alive 1103, written 1103, skipped 12 bad lines, in 27.412s
```

With `-db`, the summary also says how many results were saved there
(`saved 70000 to db`). With `-db` and no `-o`, it leaves out `written`.
With `-skip`, it says how many proxies were left out
(`left out 40 of skipped protocols`). With `-resume`, it says how
many proxies were skipped because the results file already held them
(`skipped 5000 already done`).

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The run finished, or `-h` was given. |
| `1` | An error: bad settings, unreadable input, a failed write, and so on. |
| `2` | The command line could not be parsed, or holds an argument that is not a flag: `shimmer proxies.txt` without `-i`, or a value after a switch that takes none, as in `-quiet true`. The error and the usage have already been printed. Also the Go runtime's code for a crash that could not be recovered, such as a panic inside Xray (see [Crashes](#6-crashes)); stderr then ends in `panic:` and a stack trace. |
| `130` | Interrupted by Ctrl-C (SIGINT) or SIGTERM. |

## Config file

`-config` loads a JSON file first; [`SHIMMER_` variables](#environment-and-env-file)
and then flags override it. Only flags you actually type override the file,
so the file is not overwritten by flag defaults.

```json
{
  "input": "proxies.txt",
  "output": "results.jsonl",
  "db": "proxies.db",
  "format": "jsonl",
  "workers": 512,
  "proxy_timeout": "10s",
  "mmdb_city": "GeoLite2-Country.mmdb",
  "mmdb_asn": "GeoLite2-ASN.mmdb",
  "check_exit_ip": true,
  "skip_protocols": ["socks4"]
}
```

- Every key is optional; missing keys keep their defaults.
- An unknown key is refused, so a misspelt one fails the run instead of
  quietly leaving its setting at the default. So is anything after the
  closing brace.
- An empty `"output"` counts as not given, as an empty `-o` does.
- `proxy_timeout` uses Go duration syntax: `"10s"`, `"1500ms"`, `"1m"`.
- `skip_protocols` is a list of protocol names. `-skip` replaces it
  entirely, and `-skip ""` clears it.
- Values are checked after the flags are applied, so a flag can correct a bad
  value in the file.
- `-lists`, `-fetch`, `-resume`, `-alive-only` and `-quiet` have no key in
  the file. `-fetch`, `-alive-only` and `-quiet` have `SHIMMER_` variables.
- Relative paths are resolved from the current directory, not from the config
  file's location.

## Environment and .env file

Every setting except `-lists` and `-resume` can also come from a `SHIMMER_`
variable, either in the environment or in a `.env` file. The project root has
a `.env.example` that names the geo databases next to it and lists every other
variable, commented out, at its default. Copy it to `.env`, which git ignores:
`cp .env.example .env`.

### Which setting wins

Each source overrides the ones before it:

1. Built-in defaults.
2. The `-config` JSON file.
3. The `.env` file.
4. Variables set in the environment, e.g. `SHIMMER_WORKERS=1000 ./shimmer ...`.
5. Flags typed on the command line.

An empty variable (`SHIMMER_DB=`) counts as not set. It leaves the setting to the
sources before it, and doesn't clear it.

### Variables

| Variable | Flag |
| --- | --- |
| `SHIMMER_INPUT` | `-i` |
| `SHIMMER_OUTPUT` | `-o` |
| `SHIMMER_DB` | `-db` |
| `SHIMMER_FORMAT` | `-format` |
| `SHIMMER_WORKERS` | `-workers` |
| `SHIMMER_TIMEOUT` | `-timeout` |
| `SHIMMER_EXIT_IP` | `-exit-ip` |
| `SHIMMER_SKIP` | `-skip` |
| `SHIMMER_MMDB_CITY` | `-mmdb-city` |
| `SHIMMER_MMDB_ASN` | `-mmdb-asn` |
| `SHIMMER_FETCH` | `-fetch` |
| `SHIMMER_ALIVE_ONLY` | `-alive-only` |
| `SHIMMER_QUIET` | `-quiet` |
| `SHIMMER_CONFIG` | `-config` |

- A value is read exactly as its flag's would be: `SHIMMER_TIMEOUT=1500ms`,
  `SHIMMER_EXIT_IP=true`, `SHIMMER_SKIP=socks4,http`.
- `-lists` and `-resume` have no variable. Each one changes what a run does,
  and if one were left in `.env`, every later run would quietly do that too.
- Relative paths are resolved from the current directory, as they are
  everywhere else.

### The .env file

- **Where:** `.env` in the current directory, read if it is there. Nothing
  else is searched, so `shimmer` run from another directory doesn't see the
  project's `.env`. `-env path` reads a different file, which must then exist,
  and `-env ""` reads none.
- **Syntax:** it uses the subset of `KEY=value` that Docker Compose also
  reads, so Compose can share the file.
  - Blank lines and lines starting with `#` are skipped.
  - An `export ` prefix is allowed.
  - A value may be wrapped in `"` or `'`. Quoted values are taken as written,
    with no escape sequences.
  - In an unquoted value, a `#` that follows a space starts a comment:
    `SHIMMER_WORKERS=256 # fewer`. A `#` inside a word is part of the value.
  - A variable given twice keeps its last value.
- **Mistakes are refused:**
  - An unknown `SHIMMER_` name in the file fails the run, so a misspelt one can't
    leave its setting at the default. `SHIMMER_RESUME` and `SHIMMER_LISTS` count as
    unknown. Names without the `SHIMMER_` prefix (`TZ`,
    `COMPOSE_PROJECT_NAME`, ...) are ignored.
  - A value that doesn't parse fails the run, naming the variable:
    `shimmer: invalid value "many" for SHIMMER_WORKERS: parse error`. A value that
    parses but is out of range (`SHIMMER_WORKERS=0`, `SHIMMER_SKIP=socks6`) fails as
    the same value given by flag would.
  - Unknown `SHIMMER_` names in the environment itself are not checked.

## Input

### Proxy lists (`-i`)

One proxy per line. Real lists are untidy, so all of these parse to the same
proxy:

```
1.2.3.4:8080
socks5://1.2.3.4:8080
user:pass@1.2.3.4:8080
1.2.3.4:8080:user:pass
1.2.3.4 8080
1.2.3.4,8080
1.2.3.4:8080 socks5
```

IPv6 addresses need brackets: `[2001:db8::1]:8080`.

A line starting with `vless://`, `vmess://`, `trojan://`, `ss://`,
`hysteria2://` or `hy2://` (in any case) is a share link instead, and is read
whole; see [Reading share links](#reading-share-links). The rest of this
section is about classic proxies.

- Credentials are dropped, and so is a classic proxy's scheme prefix:
  `http://`, `https://`, `socks://`, `socks4://`, `socks4a://`, `socks5://`
  or `socks5h://`, in any case. The scheme is not used as a hint: the
  protocol is always detected.
- A line under any other scheme (`ssr://`, `tuic://`, `wireguard://`, ...) is
  a bad line. Its server is not checked as a classic proxy.
- Blank lines, lines starting with `//`, and everything after a `#` are
  ignored. A byte-order mark at the start of the file is ignored.
- The host must be an IP address or a name made of letters, digits, `-`, `.`
  and `_`, at most 253 bytes long. The port must be 1–65535.
- A line that doesn't parse is counted in the summary as a bad line and
  skipped. It does not stop the run.
- A line longer than 1 MiB (for example, an HTML page served in place of a
  list) is counted as one bad line and skipped.
- Not understood: `user:pass:host:port`, a trailing slash
  (`http://1.2.3.4:8080/`), and unbracketed IPv6 with a port.

### Remote lists (`-lists`)

The file holds `http://` or `https://` URLs, one per line, with `#` comments
and blank lines allowed.

- Lists are downloaded `-fetch` at a time. Each one is parsed while it
  downloads, so checking starts before the last list has arrived.
- A list is read only as fast as its proxies are checked, so there is no limit
  on a whole download. A server gets 30 seconds to start answering, and a
  download that sends nothing for 1 minute is abandoned.
- Anything other than `200 OK` counts as a failed list.
- A download that fails part way keeps the entries read before it failed. The
  line it was cut in is dropped, not read as an entry: half an address is
  another address, and half a share link another link.
- If at least one list delivered lines, failed lists are reported on stderr and
  the run still succeeds. If none did, the run fails with exit code 1.
- The same proxy appearing in several lists is checked and written once per
  appearance.
- A list must be plain text, one entry per line. Many subscription URLs
  serve their links as one block of base64 instead; those are not decoded,
  and come out as bad lines.

## How one proxy is checked

The data flows through these stages:

```
source (file, stdin or URLs)
  -> resume filter (drops proxies already done, with -resume)
  -> worker pool (-workers goroutines)
       -> TCP connect
       -> protocol ladder: SOCKS5, SOCKS4, HTTP (-skip protocols last)
       -> exit address and geo lookup
  -> writers: results file (JSONL or CSV), SQLite database, or both
```

Each worker takes one proxy at a time. Nothing is buffered per worker, so a
slow writer slows the pool down instead of letting memory grow.

### 1. The time budget

Everything done for one proxy shares a single deadline, `-timeout`
(default 10s). With `-exit-ip`, protocol detection gets three quarters of it,
so the exit-address check always has at least a quarter left.

### 2. TCP connect

The program first opens and closes one TCP connection to the proxy. Most
entries in a scraped list are simply dead, and this rejects them for the cost
of one handshake. It also gives the `connect_ms` value.

### 3. Protocol ladder

The protocols are tried in order, and the first one that works decides the
result:

1. **SOCKS5.** Greeting offering "no authentication", then CONNECT to the
   check host by name, so the proxy's own DNS is used. Proxies that demand a
   password are not supported.
2. **SOCKS4.** CONNECT with the check host's IPv4 address, which is resolved
   once per run and shared. If that lookup fails, SOCKS4a (hostname in the
   request) is used for that attempt.
3. **HTTP.** Two attempts:
   - **CONNECT tunnel:** a TLS handshake to `www.gstatic.com:443` through the
     tunnel, with the certificate verified. It gets half of the time left.
     Success gives protocol `https`.
   - **Absolute-URI request:** `GET http://www.gstatic.com/generate_204`. Used
     when CONNECT fails, with all of the time still left. Success gives
     protocol `http`.

Each rung of the ladder gets an equal share of the time that is left, so a
host that accepts TCP and then stalls cannot use up the budget of the
protocols after it.

SOCKS attempts also have a cap on the proxy's **first reply**. A real SOCKS
server answers within a few round trips. A host that stays silent is almost
always something else, usually an HTTP proxy waiting for the end of a request
line that SOCKS bytes never send.

- SOCKS5 greeting: `max(1s, 4 × connect time)`.
- SOCKS4 reply: the same plus 2s, because SOCKS4 answers only after it has
  connected onward to the check host.

Only the first reply is capped. After it, the attempt keeps its full share,
so a SOCKS proxy with a slow onward connection is not cut short.

### Skipping protocols

`-skip` (or `skip_protocols` in the config file) keeps proxies of the named
protocols out of the results:

```bash
./shimmer -i proxies.txt -o results.jsonl -skip socks4,http
```

- Names are `socks5`, `socks4`, `https` and `http`, lower case, separated by
  commas. Spaces around them are ignored.
- The protocols not skipped are tried first, in the usual order, with the
  whole time budget shared between them. A proxy one of them works on is
  recorded as usual.
- Only when none of them works are the skipped protocols tried, with the time
  that is left. A proxy one of them works on is **left out**: nothing is
  written to the `-o` file, and with `-db` its row is deleted from `live` or
  `dead`, whichever an earlier run put it in. The summary counts it as
  checked, but not as alive or saved.
- A proxy nothing works on is recorded as dead, as usual. Its error lists the
  skipped protocols' failures too.
- `https` and `http` are the two HTTP attempts, and can be skipped separately.
  With `-skip https`, a proxy that also forwards absolute-URI requests is
  recorded as `http`, and one that only tunnels is left out. With
  `-skip http`, CONNECT gets all of the HTTP time instead of half of it.
- Skipping all four classic protocols is allowed: share links are still
  checked, and a classic proxy is only tried with the skipped protocols, to
  tell a proxy to leave out from a dead one.
- The link protocols `vless`, `vmess`, `trojan`, `ss` and `hysteria2` can be
  skipped too. A link names its protocol, so a link of a skipped protocol is
  left out at once, without a connection.
- An unknown name, or skipping all nine, is refused before the run starts.

### 4. Proof of forwarding

Completing a handshake is not enough to count as alive. Plenty of hosts finish
a SOCKS negotiation and then drop the payload, and captive portals and web
servers answer anything. Every probe sends a real request for
`http://www.gstatic.com/generate_204` (over TLS, for the CONNECT probe) and
requires exactly status **204**. Any other answer, including 200 or a
redirect, means the reply did not come from the real endpoint.

The request does not ask the endpoint to close the connection; the probe
hangs up once it has the status. The exit-address request does the same. An
endpoint asked to close does so right behind its answer, a share link's
server passes that on as a WebSocket close frame, and Xray then discards
whatever of the answer has not been read yet: a working WebSocket link came
out dead, more often the more workers ran.

### 5. Exit address and geography

These steps run only for proxies found alive. A failure here leaves the proxy
alive, because the probe has already proved it forwards traffic.

- **With `-exit-ip`:** `https://api.ipify.org` is fetched through the proxy
  the way it was seen to work. `socks5`, `socks4` and `https` proxies use a
  tunnel. `http` proxies can't tunnel, so they get the cleartext
  `http://api.ipify.org`, whose answer the proxy could in principle rewrite.
  If the check fails, `exit_ip`, `country` and `asn` are left empty rather than
  guessed.
- **Without `-exit-ip`:** the proxy's own address stands in as `exit_ip`, if
  it is an IP literal. That is right only for proxies that don't relay onward
  through another address.
- **Geo lookup:** the exit address is looked up in the databases given.
  `country` is the ISO 3166-1 alpha-2 code; when the database has no country
  for the address, the registered country of the address block is used
  instead. `asn` comes from the ASN database. The organisation name is read
  but not written to the output.

### 6. Crashes

A panic while checking one proxy is recovered. That proxy is recorded as dead
with the error `probe panicked: ...`, and the first 3 stack traces are printed
to stderr, even with `-quiet`. The run continues, and the summary reports how
many probes panicked.

This covers the goroutine that checks the proxy. A share link's traffic also
runs through goroutines that Xray starts itself, and a panic in one of those
cannot be recovered: it ends the process. Links known to cause one are
refused as bad lines when they are read (see
[Reading share links](#reading-share-links)).

## Share links

A share link carries everything a client needs to connect: the server, the
credentials, the transport and its TLS settings. `shimmer` builds an Xray
outbound from each link, sends the same check request through it that a
classic proxy gets, and records the result in the same shape.

### Reading share links

| Scheme | Forms read |
| --- | --- |
| `vless://` | `uuid@host:port?params#name` |
| `trojan://` | `password@host:port?params#name`. With no `security` given, TLS, as clients assume. |
| `vmess://` | base64 of v2rayN's JSON (`add`, `port`, `id`, `net`, `tls`, ...), or `uuid@host:port?params#name` |
| `ss://` | SIP002 (`base64(method:password)@host:port#name`, or the plain `method:password` form AEAD-2022 links use), or the original `base64(method:password@host:port)#name` |
| `hysteria2://`, `hy2://` | `auth@host:port/?sni=...&obfs=salamander&obfs-password=...#name` |

- Parameters are read in any case (`serviceName`, `servicename`), under the
  names clients use: `type`, `security`, `sni`, `host`, `path`, `alpn`, `fp`,
  `pbk`, `sid`, `spx`, `pqv`, `flow`, `encryption`, `serviceName`,
  `authority`, `mode`, `extra`, `headerType`, `ech`, `pcs`, `vcn`,
  `allowInsecure` / `insecure`.
- **Transports:** raw/TCP (with the HTTP header disguise), WebSocket, gRPC,
  HTTPUpgrade, XHTTP (with `mode` and `extra`), mKCP, and Hysteria2's QUIC.
- **Security:** none, TLS (with uTLS fingerprints, ALPN, ECH and pinned
  certificates) and REALITY.
- With TLS and no `sni`, the first `host` is used, then the server's name if
  it is not an IP address.
- `allowInsecure=1` is honoured, as clients honour it. Xray refuses that
  setting in its JSON since 2026-06-01, so it is applied to the outbound
  after it is built.
- The `#name` is kept as the record's `name`. A `#` in a share link starts its
  name, not a comment.
- An `@` after the `?` belongs to the query, so a note some lists add, such as
  `ss://...@host:port?note=@channel`, leaves the server as it is.

A link is a bad line, counted in the summary and skipped, when no client
could connect with it:

- `ssr://` and other schemes: not read at all.
- Shadowsocks with a stream cipher (`aes-256-cfb`, `rc4-md5`, `chacha20-ietf`,
  ...) or a SIP003 `plugin`: Xray has neither.
- Transports Xray has removed: `http`/`h2`, `quic`, and mKCP with a `seed` or
  header.
- REALITY without a public key, an unknown `type` or `security`, an `extra`
  that is not JSON, a missing id or password, or a malformed address.
- XHTTP whose request URL does not parse: a `host`, or with no `host` an
  `sni`, that is not a host name (such as `name@channel`), or a control byte
  in the query part of `path`. Xray builds that URL without checking it, and
  crashes the whole process on it.

### How a link is checked

The time budget, and the quarter of it kept for `-exit-ip`, are the same as
for a classic proxy.

1. **TCP connect** to the server, as for a classic proxy: it rejects dead
   servers for the cost of one handshake, and gives `connect_ms`. Links over
   UDP (Hysteria2, mKCP, XHTTP offering only `h3`) skip it, and their
   `connect_ms` is 0.
2. **Outbound.** The link becomes an Xray outbound of its own, under a tag of
   its own, in the one Xray instance the run shares.
3. **Proof of forwarding.** `GET http://www.gstatic.com/generate_204` goes
   through the outbound, and exactly **204** must come back, as for a classic
   proxy. The server resolves the check host itself. `total_ms` is the time
   from this request's start to the answer, the handshake with the server
   included.
4. **Exit address.** With `-exit-ip`, `https://api.ipify.org` is asked through
   the same outbound.
5. The outbound is removed, and every socket it opened is closed. Xray's gRPC,
   XHTTP and Hysteria2 transports keep connections in pools that are never
   emptied, so without this each such link would leave one behind.

A dead link's `error` is Xray's reason, shortened to its cause: for example
`dial tcp 1.2.3.4:443: connect: connection refused`, `failed to dial
WebSocket > ... 403 Forbidden > websocket: bad handshake`, or `EOF` for a
server that hung up without one, which is how REALITY and Shadowsocks servers
answer a wrong key.

Xray's own log is discarded, so nothing but results reaches stdout.

## Output

One record per proxy checked (per alive proxy, with `-alive-only`), in the
order the checks finish, not the input order. Proxies left out by
[`-skip`](#skipping-protocols) get no record.

### JSONL

```json
{"host":"203.0.113.7","port":1080,"protocol":"socks5","alive":true,"connect_ms":41.2,"total_ms":187.5,"exit_ip":"198.51.100.4","country":"DE","asn":64500,"checked_at":"2026-09-23T18:40:00.123+03:00"}
{"host":"203.0.113.8","port":8080,"protocol":"unknown","alive":false,"connect_ms":10000,"total_ms":0,"error":"dial tcp 203.0.113.8:8080: i/o timeout","checked_at":"2026-09-23T18:40:00.456+03:00"}
{"host":"198.51.100.20","port":443,"protocol":"vless","transport":"raw","security":"reality","alive":true,"connect_ms":38.1,"total_ms":412.7,"exit_ip":"198.51.100.20","country":"NL","asn":64501,"checked_at":"2026-09-23T18:40:01.002+03:00","name":"NL-1","link":"vless://...@198.51.100.20:443?security=reality&...#NL-1"}
```

### CSV

The same fields as columns, with a header row:

```
host,port,protocol,alive,connect_ms,total_ms,exit_ip,country,asn,error,checked_at,transport,security,name,link
```

In CSV an unknown ASN is written as `0`, and `checked_at` has whole seconds.
The link columns are last, and empty for classic proxies, so a file started
by an older build keeps its columns in place and can still be resumed.

### Fields

| Field | Meaning |
| --- | --- |
| `host`, `port` | The proxy, as it was parsed from the input. For a share link, its server. |
| `protocol` | `socks5`, `socks4` (includes SOCKS4a), `https` (CONNECT tunnels work), `http` (only absolute-URI requests work), or `unknown` for dead proxies. For a share link, the protocol it names, `vless`, `vmess`, `trojan`, `ss` or `hysteria2`, alive or dead. |
| `transport`, `security` | Share links only: `raw`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `kcp` or `hysteria`; `none`, `tls` or `reality`. |
| `alive` | `true` only if a request through the proxy got the check endpoint's own 204. |
| `connect_ms` | TCP handshake time to the proxy. For a proxy that never connected, this is the time until the connection failed. |
| `total_ms` | The successful probe from its own connect to the answer, including the onward fetch. `0` for dead proxies. |
| `exit_ip` | See [Exit address and geography](#5-exit-address-and-geography). Left out when unknown. |
| `country`, `asn` | From the geo databases. Left out when unknown. |
| `error` | Why the proxy is dead: every protocol's failure, joined with `; `. Always one line. |
| `checked_at` | When the check finished, including the exit-address check and geo lookup. |
| `name`, `link` | Share links only: the link's name (its `#` part, or `ps` in vmess), and the link as it was read. |

Records are flushed every 256 results and when the run ends. A crash or kill
loses at most the records that had not been flushed yet, and `-resume` checks
those proxies again.

### SQLite database (`-db`)

`-db proxies.db` keeps the results in a SQLite database as well as, or
instead of, the `-o` file. It is made for a list you check again and again:

- **Live and dead are kept apart.** The table `live` holds the proxies that
  work, and `dead` holds the ones that don't. Each proxy is in exactly one of
  them: a check puts it in the table for its result and removes it from the
  other one. A proxy [left out by `-skip`](#skipping-protocols) is removed
  from both.
- **One row per proxy, the latest.** `(host, port)` is the key, and hosts are
  compared case-insensitively. A proxy checked again, in the same run or a
  later one, has its row replaced, not duplicated. No history is kept.
- **Never emptied.** A new run adds to what is there, and removes only the
  proxies `-skip` leaves out. Delete the file to start again.
- **Every result goes in.** `-alive-only` applies to the `-o` file only.
- **Rows are in no particular order.** Add an `ORDER BY` when reading if you
  need one.

```
live: host, port, protocol, connect_ms, total_ms, exit_ip, country, asn, checked_at
dead: host, port, connect_ms, error, checked_at
```

Share links have tables of their own, `live_links` and `dead_links`, and
never go into `live` or `dead`:

```
live_links: id, protocol, transport, security, host, port, name, link, connect_ms, total_ms, exit_ip, country, asn, checked_at
dead_links: id, protocol, transport, security, host, port, name, link, connect_ms, error, checked_at
```

- **Keyed by `id`, not by address.** Hundreds of links can share one server
  (a CDN address fronts many), so `id` is a hash of what a link connects
  with: protocol, server, credentials, transport and security. Two links that
  differ only in their names, or in how their parameters are spelt, are one
  row, holding the latest name and link.
- The rest works as for classic proxies: one table per outcome, the latest
  result per link, never emptied, and a link left out by `-skip` removed from
  both.

The fields mean what they do in the [results file](#fields). A value that is
unknown (`exit_ip`, `country`, `asn`, or a missing `error`) is `NULL`.
`checked_at` is RFC 3339 text with fractional seconds.

Rows are committed every 256 results and when the run ends, including after
Ctrl-C. The database uses write-ahead logging, so it can be read while a run
writes to it; `proxies.db-wal` and `proxies.db-shm` next to it are part of
it while it is open.

Only one run should write to a database at a time. Each batch of 256 results
holds the write lock until it commits, which on a slow run can take minutes,
so a second run on the same file waits 5 seconds and then fails with
"database is locked".

```bash
sqlite3 proxies.db "SELECT host, port, protocol, country FROM live"
```
```bash
sqlite3 proxies.db "SELECT count(*) FROM dead"
```
```bash
sqlite3 proxies.db "SELECT link FROM live_links ORDER BY total_ms"
```

## Resuming an interrupted run

With `-resume`, the results file is its own checkpoint; no other state is kept.

1. The existing `-o` file is read, and every proxy in it is remembered. Hosts
   are compared case-insensitively, as 64-bit hashes, so a huge file costs
   little memory. A share link is remembered by what it connects with, as the
   database's `id` is, so the same link under another name counts as done,
   and another link on the same server does not.
2. The input is read as usual, and remembered proxies are skipped.
3. New results are appended to the same file.

Details:

- `-resume` needs `-o` to name a file. A missing file just starts from
  nothing.
- A run killed mid-write leaves a partial last line. It is cut off before
  appending, and that proxy is checked again.
- Before the run starts, stderr says how many proxies the file already holds:
  `shimmer: resuming results.jsonl, 5000 proxies already done`. The summary
  counts the proxies in the input that were skipped because of it
  (`skipped 5000 already done`).
- Records that can't be read are ignored, not removed, and their proxies are
  checked again. Their count is added to the first line
  (`, 1 unreadable records ignored`). In CSV, reading stops at the first
  malformed row.
- The file's format must match `-format`. A CSV file resumed as JSONL (or the
  other way round) is refused with a message naming the right `-format`,
  instead of being appended to in a second format.
- A run started with `-alive-only` wrote nothing for dead proxies, so resuming
  it checks the dead ones again. Resume is exact only for a file that holds
  every result.
- Resume reads only the `-o` file, never the database. A database needs no
  resuming: a proxy checked again just gets its row replaced.

## Geo databases

The project root currently holds three MaxMind GeoLite2 databases:

| File | Size | Used for |
| --- | --- | --- |
| `GeoLite2-Country.mmdb` | 8.5 MB | `country`, via `-mmdb-city` |
| `GeoLite2-City.mmdb` | 66 MB | `country`, via `-mmdb-city` |
| `GeoLite2-ASN.mmdb` | 12 MB | `asn`, via `-mmdb-asn` |

- Only the country code is read from the "city" database, so the Country
  database gives the same answers as City at an eighth of the size.
- Either flag can be used on its own; the other field then stays empty.
- Lookups are offline and fast, and both databases are safe to share between
  workers.

### Where the files go

The files can live anywhere. `shimmer` never searches for them and has no
default path: each database is used only when its path is given, by
`-mmdb-city` / `-mmdb-asn`, by `SHIMMER_MMDB_CITY` / `SHIMMER_MMDB_ASN`, or by
`mmdb_city` / `mmdb_asn` in the config file. With no path given, the lookup is
off and `country` and `asn` stay empty.

- **Absolute paths** work from any directory.
- **Relative paths** are resolved from the directory `shimmer` runs in. They are
  not resolved from the binary's location, and not from the location of the
  config file or `.env` file that names them.
- **The project root** holds the files, and its `.env` names them by relative
  path. Run from the root, `./shimmer` finds them with no flags. From anywhere
  else, give absolute paths:

  ```bash
  shimmer -i proxies.txt -mmdb-city /path/to/shimmer/GeoLite2-Country.mmdb -mmdb-asn /path/to/shimmer/GeoLite2-ASN.mmdb
  ```

- **Docker:** the working directory in the container is `/data`, so the files
  must be in the directory mounted there. `compose.yaml` mounts the project
  root, which already holds them. With `docker run -v "$PWD:/data"`, run it
  from the directory that holds them. The image itself has none.
- **A wrong path** stops the run before anything is written, with
  `open city database: ...` or `open ASN database: ...`. The run does not
  continue without geo data.

### Getting and updating them

GeoLite2 needs a free MaxMind account and license key. Either download the
files from the account portal, or install `geoipupdate`
(`brew install geoipupdate`), put the account ID, license key and
`EditionIDs GeoLite2-Country GeoLite2-ASN` into
`$(brew --prefix)/etc/GeoIP.conf`, and run `geoipupdate`.

### Licence terms to respect

The GeoLite2 EULA:

- **Forbids passing the databases to anyone else** without MaxMind's written
  consent. Don't commit the `.mmdb` files to a shared repository, and don't
  embed them in a binary you give away.
- **Requires old copies to be deleted within 30 days** of a new release.
  GeoLite2 is updated about twice a week, so refresh at least monthly.
- **Requires attribution:** "This product includes GeoLite Data created by
  MaxMind, available from https://www.maxmind.com".

If the databases must ship with the program, DB-IP's *IP to Country Lite* and
*IP to ASN Lite* are CC BY 4.0 (redistribution allowed, with attribution),
come in MMDB format, and are built for GeoIP2 readers. Check a lookup before
relying on their field names.

### Accuracy

IP geolocation is an estimate, and vendors disagree on individual addresses,
especially below country level. A location that looks wrong can be reported
to MaxMind at https://www.maxmind.com/en/geoip-location-correction.

## Run behaviour and safety

- **Output that is also the input is refused**, however the two paths are
  spelled (links, `..`, or stdin redirected from the same file). Opening the
  output empties it, so the list would be gone before it was read.
- **An output that is the database is refused**, however the two paths are
  spelled, and before the database is opened. Opening the results file would
  empty the database.
- **An output that is a geo database, the config file or the .env file is
  refused** too.
  The geo readers map their files, so emptying one would also kill the
  process with a bus error at the first lookup.
- **The output is opened last**, after the settings, the input, the geo
  databases and the SQLite database have all been checked. A typo in a
  database path, or a `-db` file that is not a SQLite database, fails without
  emptying the previous results.
- **Worker count vs. open-file limit:** on unix, workers are capped at the
  open-file limit minus 32, with a notice on stderr. On macOS the limit is
  the smaller of the soft limit and `kern.maxfilesperproc`, so a shell that
  ran `ulimit -n unlimited` still gets a cap.
- **Ctrl-C / SIGTERM:** probes in flight are cancelled, results already
  written are flushed, the summary is printed, and the exit code is 130.
  Results that had finished but were not yet written are dropped; `-resume`
  checks those proxies again.
- **Input errors:** if a local list fails part way, the run exits with
  code 1, even though the results it did write are kept. The rest of the list
  was never checked.

## Code layout

```
cmd/shimmer/            command: flags, wiring, progress, summary, exit codes
  main.go
  rlimit_unix.go        reads the open-file limit
  rlimit_darwin.go      macOS's own cap on open files, kern.maxfilesperproc
  rlimit_notdarwin.go   no such cap on other unix systems
  rlimit_other.go       no limit handling outside unix
internal/config/        Config, defaults, JSON config file, .env reader,
                        validation
internal/source/        proxy line parser, file/stdin streaming, remote lists
internal/link/          share-link parser: vless, vmess, trojan, ss and
                        hysteria2 links to Xray outbound JSON, and link ids
internal/xray/          the embedded Xray-core: one instance per run, an
                        outbound per link, the dialer that tunnels through
                        it, and the socket tracker that closes pooled
                        connections when a link's check ends
internal/probe/         SOCKS5/SOCKS4/HTTP probers, the ladder, connect time,
                        the share-link check, and a dialer that tunnels
                        through a checked proxy
internal/pipeline/      worker pool, per-proxy deadline, panic recovery,
                        the -skip pass, exit address and geo enrichment
internal/geo/           Lookup interface, MaxMind reader, exit-IP echo client
internal/store/         JSONL and CSV writers, append mode, torn-tail trimming,
                        and the SQLite store with its live and dead tables
internal/resume/        reads earlier results, filters proxies already done
internal/dial/          the Dialer interface every outbound connection uses
Dockerfile              static build, run FROM scratch as a non-root user
compose.yaml            runs the image with the project directory at /data
.env.example            SHIMMER_ settings to copy to .env
.env                    SHIMMER_ settings, read from the directory shimmer runs in;
                        not in git
```

Design points that shape the code:

- **One dialer seam.** Every outbound connection goes through `dial.Dialer`.
  Tests substitute their own, and `probe.Dialer` wraps a checked proxy so the
  exit-IP lookup can run through it unchanged. A share link's tunnel is a
  `dial.Tunnel`, the same seam with a `Close`, and the pipeline sees Xray
  only through it. The exception is Xray's own connection to a link's
  server, which goes through Xray's system dialer.
- **Streams everywhere.** Sources emit on a buffered channel (1024 entries),
  workers pull one proxy at a time, and a single goroutine owns the writer, so
  the store needs no locking.
- **Deadlines are tied to sockets.** A context deadline becomes the socket
  deadline, and cancelling the context unblocks any read or write in flight,
  so no probe can outlive its budget.
- **Reads from proxies are bounded.** Status and header lines are read with a
  fixed buffer, so a peer that streams bytes without a newline costs one
  buffer, not unbounded memory.

## Testing

```bash
go vet ./...
```
```bash
go test -race ./...
```

- The tests use fake proxies and servers on localhost and need no network.
  The share-link tests start real Xray servers in the test process (VLESS,
  VLESS and VMess over WebSocket, Trojan over gRPC, Shadowsocks, TLS with a
  self-signed certificate, and Hysteria2 over QUIC) and check through them.
- `TestWebSocketLinkOutlivesTheAnswer` in `internal/xray` checks one working
  WebSocket link 60 times, 8 at once, and fails if any check loses its
  answer. It is kept that small on purpose: a few thousand loopback
  connections in a second make macOS drop SYNs, and checks then time out for
  a reason that has nothing to do with the code.
- A full run takes about 20 seconds; `internal/probe` is the slowest package
  because it exercises real timeouts. The first build compiles Xray-core,
  which takes a minute or so.
- `TestMainProcess` in `cmd/shimmer` is skipped in a normal run. Other tests start
  the test binary as a child process through it, to check exit codes and
  stderr.

## Known limitations

These were found in review and have not been changed:

- After Ctrl-C, the summary's "checked" count includes probes that were
  cancelled and never written.
- A second Ctrl-C does nothing while the program is shutting down, or while
  `-resume` is loading a large results file.
- `connect_ms` for a dead proxy is the time until the failure (often the full
  timeout), not a handshake time, so sorting by it mixes the two.
- If the city lookup fails for an address, its ASN is not recorded either.
- Falling back to the registered country can label an address with the
  country its block was allocated in, not where it is used.
- Loopback, private and unspecified addresses are accepted as proxies. A
  downloaded list can therefore make the program send SOCKS and HTTP bytes to
  services on your own machine or network.
- Duplicate proxies, within a list or across lists, are checked and written
  once per copy. The database keeps one row per proxy, but each copy is still
  checked.
- A proxy that supports CONNECT but can't finish the TLS check within its half
  of the HTTP time is recorded as `http` rather than `https`. `-skip http`
  gives CONNECT all of the HTTP time.
- A proxy left out by `-skip` is not in the `-o` file, so `-resume` checks it
  again.
- `-skip` recognises a proxy of a skipped protocol only in the time the wanted
  protocols leave. One that keeps a wanted protocol waiting until the time
  runs out is recorded as dead instead of left out, and with `-db` moved into
  `dead`.
- Local failures (network down, too many open files) are recorded as dead
  proxies, and `-resume` will then skip them. In the database they also move
  proxies that were live before into `dead`: a run made while offline empties
  `live`.

Share links:

- Without `-exit-ip`, a link's server address stands in as `exit_ip`, as for a
  classic proxy. For a link fronted by a CDN, that is the CDN's address, not
  where its traffic leaves.
- Xray retries a failed connection to a server a few times, so a link whose
  server accepts TCP and then fails its TLS or REALITY handshake takes about
  2 seconds to be found dead, not one round trip.
- Hysteria2 port hopping (`mport`) is ignored: only the link's own port is
  used.
- Xray keeps a gRPC client for every gRPC link it has dialed, in a pool of
  its own that nothing outside Xray can empty. `shimmer` closes its socket when
  the link's check ends and refuses its reconnects, but the client itself
  stays: 4 goroutines and about 30 KiB for each gRPC link checked, measured,
  so about 3 GB for 100,000 of them. A list of mostly gRPC links that large
  is better split across runs.
- A link with `ech=domain+udp://resolver` makes Xray look the ECH
  configuration up through that resolver. Where the answer is not a valid
  ECH configuration, as with the widely copied `ip.gs+udp://8.8.8.8`, the link
  is recorded dead with `tls: malformed ECHConfigList`, as it would fail in a
  client.
- Many links of one CDN-fronted server checked at once can draw
  `429 Too Many Requests` from the CDN, and be recorded dead. Fewer
  `-workers` helps.
- Base64-encoded subscription bodies are not decoded; see
  [Remote lists](#remote-lists--lists).
- A panic inside Xray's own goroutines ends the run (see
  [Crashes](#6-crashes)). The link that caused it gets no record, so
  `-resume` checks it again and the same crash follows. The one cause found
  so far, an XHTTP request URL that does not parse, is refused when the link
  is read.
- A link whose outbound Xray refuses to build (a REALITY key of the wrong
  length, an id that is not a UUID) is recorded dead with `outbound: ...`,
  not counted as a bad line.
- Passing the check proves a link forwards traffic to `www.gstatic.com`. Some
  servers forward to nothing else. They are recorded alive, and with
  `-exit-ip` their `exit_ip` stays empty, because the echo service can't be
  reached through them.
