# binhttp — HTTP, in binary

Course project: *Network Architecture — two tracks, one protocol.*

| Hand-in item | Where |
|---|---|
| 1. The spec (two pages, enough for a stranger) | [SPEC.md](SPEC.md) (printable: [docs/SPEC.pdf](docs/SPEC.pdf)) |
| 2. The programs | [src/bserve.c](src/bserve.c) (Track 1, server), [src/bcurl.c](src/bcurl.c) (Track 2, client), [src/bhttp.c](src/bhttp.c) (shared framing) |
| 3. Annotated hexdump of one complete request and response | [HEXDUMP.md](HEXDUMP.md) |

## Build and run

Needs a C11 compiler and `make` (macOS or Linux). There are no dependencies.

```bash
make
```

```bash
./bserve ./www 9000
```

In a second terminal:

```bash
./bcurl -v localhost:9000/index.html
```

## Track 1 — `bserve`

```
usage: bserve [-v] [-g] <root-dir> <port>
  -v  hexdump every frame to stderr
  -g  send an unknown frame type before each response (tests client skipping)
```

* Accepts TCP connections, one process per connection, on IPv4 and IPv6.
* Reads binary request frames and maps `:path` to a file under the root. `/` and directories get `index.html`. Percent-decoding is applied, `..` is refused, and symlinks may not lead outside the root.
* Replies with `:status`, headers and the file bytes, split into DATA frames of up to 16 KiB.
* **404** if the file is not there. **400** if the frame is malformed. Also 403 (outside the root), 405 (not GET/HEAD) and 505 (wrong major version).
* **Keeps the connection open** after each response, including after a 404 or a header-block 400. It only hangs up when the framing itself can't be trusted (SPEC §6), or after 60 s idle.
* Skips unknown frame types and ignores unknown flag bits and reserved header indexes.
* Logs one line per request to stderr: `[::1]:61269 GET /nope -> 404`.

## Track 2 — `bcurl`

```
usage: bcurl [-v] [-I] [-g] [-H 'name: value']... URL [URL...]
  URL  [bhttp://]host[:port][/path]   (default port 9000)
  -v   hexdump every frame to stderr
  -I   HEAD instead of GET
  -g   send an unknown frame type before each request (tests server skipping)
  -H   extra request header (repeatable; sent as a literal name)
```

* Builds the binary request frame and writes the body to stdout byte for byte, so binary files are safe to redirect.
* `-v` hexdumps **every** frame, both directions, including the preface, and decodes each header block.
* **Exit codes:** `0` = 2xx/3xx, `4` = some 4xx, `5` = some 5xx, `3` = protocol error, `2` = cannot connect, `1` = usage error.
* **Never opens a second connection.** All URLs on the command line go over one TCP connection. If two URLs name different host:port pairs, bcurl refuses before it connects.
* Checks the server's preface and the req_id echo, checks that the body matches `content-length`, and skips unknown frame types.

## Tests: is it a protocol or just an implementation?

```bash
make test
```

[tests/conformance.py](tests/conformance.py) is a **second implementation of the wire format, written in Python from SPEC.md alone**. It shares no code with `src/`. It runs 48 checks:

* **Server, normal use:** keep-alive (20 requests on one connection), pipelining with arbitrary req_ids, a 1 MB binary file byte-exact across many DATA frames, HEAD, empty files, directory index, query strings, a request fed one byte at a time, and concurrent connections.
* **Server, the version-2 rule:** unknown frame types (including a 100 KB one, and one placed between HEADERS and DATA), unknown flag bits, reserved header indexes and literal-coded table names are all skipped or accepted.
* **Server, 400s that keep the connection:** fields that overrun the block, truncated literals, missing or duplicate pseudo-headers, `:status` in a request, uppercase names, CR/LF in values (header injection), req_id 0, bad percent-escapes.
* **Server, errors that close the connection:** an HTTP/1.1 client, a version 2 preface (505), DATA with no request open, an oversized header block, a truncated frame.
* **Path safety:** `/../`, `%2e%2e`, and a symlink that points outside the root.
* **Client, against mock servers that are not bserve:** 5 URLs over exactly 1 connection, a server that sends junk frame types, odd flags, literal and reserved fields, and a body split into 1-byte DATA frames, plus 5xx exit codes, a non-BHTTP server, a short body and a server that hangs up mid-response.

The whole suite also passes with the binaries built under AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
make clean && make CFLAGS="-std=c11 -g -fsanitize=address,undefined" && python3 tests/conformance.py
```

## Layout

```
SPEC.md                 the protocol (hand-in 1)
HEXDUMP.md              annotated request + response (hand-in 3)
src/bhttp.{h,c}         framing, header-block codec, -v tracing
src/bserve.c            server
src/bcurl.c             client
www/                    sample document root
tests/conformance.py    independent implementation + 48 tests
tools/annotate.py       decodes a `bcurl -v` trace into the annotated tables
docs/                   raw captures used for HEXDUMP.md, SPEC.pdf
```
