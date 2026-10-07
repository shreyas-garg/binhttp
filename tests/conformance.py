#!/usr/bin/env python3
"""
Conformance tests for BHTTP/1.

This file is a SECOND, independent implementation of the wire format,
written from SPEC.md alone (it shares no code with src/). It is used to:

  * attack bserve with well-formed, malformed and unknown input, and
  * run bcurl against mock servers that are NOT bserve.

"A client that only works against your own server is an implementation,
not a protocol." These tests are how we check it is a protocol.

Run:  make test      (or: python3 tests/conformance.py)
"""
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BSERVE = os.path.join(ROOT, "bserve")
BCURL = os.path.join(ROOT, "bcurl")

# ---------------------------------------------------------------- wire format

PREFACE = b"BH\x01\x00"
DATA, HEADERS = 0x00, 0x01
END_STREAM = 0x01
STATIC = [None, ":method", ":path", "host", "user-agent", "accept",
          ":status", "content-type", "content-length", "server", "date"]


def frame(ftype, flags, req, payload=b""):
    return struct.pack(">IBBH", len(payload), ftype, flags, req) + payload


def field(name, value, force_literal=False):
    if isinstance(value, str):
        value = value.encode()
    if name in STATIC and not force_literal:
        return bytes([STATIC.index(name)]) + struct.pack(">H", len(value)) + value
    n = name.encode()
    return b"\x00" + bytes([len(n)]) + n + struct.pack(">H", len(value)) + value


def block(*pairs):
    return b"".join(field(n, v) for n, v in pairs)


def request_block(path, method="GET", extra=()):
    return block((":method", method), (":path", path), ("host", "test"),
                 ("user-agent", "conformance.py"), ("accept", "*/*"), *extra)


def decode_block(b):
    out, i = [], 0
    while i < len(b):
        idx = b[i]; i += 1
        if idx == 0:
            n = b[i]; i += 1
            name = b[i:i + n].decode(); i += n
        else:
            name = STATIC[idx] if idx < len(STATIC) else None
        vlen = struct.unpack(">H", b[i:i + 2])[0]; i += 2
        value = b[i:i + vlen]; i += vlen
        if len(value) != vlen:
            raise ValueError("header block overrun")
        if name is not None:          # reserved index: ignore (SPEC §5)
            out.append((name, value.decode()))
    return out


class Conn:
    def __init__(self, port, host="127.0.0.1", preface=True):
        self.s = socket.create_connection((host, port), timeout=5)
        if preface:
            self.s.sendall(PREFACE)
            assert self.recv_exact(4) == PREFACE, "server preface"

    def send(self, data):
        self.s.sendall(data)

    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise EOFError("closed after %d/%d bytes" % (len(buf), n))
            buf += chunk
        return buf

    def read_frame(self):
        length, ftype, flags, req = struct.unpack(">IBBH", self.recv_exact(8))
        return ftype, flags, req, self.recv_exact(length)

    def response(self):
        """Read one complete response, skipping unknown frame types."""
        r = {"frames": [], "body": b"", "headers": None}
        while True:
            ftype, flags, req, payload = self.read_frame()
            r["frames"].append((ftype, flags, req, len(payload)))
            if ftype == HEADERS:
                assert r["headers"] is None, "two HEADERS in one response"
                r["headers"] = dict(decode_block(payload))
                r["req"] = req
            elif ftype == DATA:
                assert r["headers"] is not None, "DATA before HEADERS"
                r["body"] += payload
            if flags & END_STREAM and ftype in (DATA, HEADERS):
                break
        r["status"] = int(r["headers"][":status"])
        return r

    def get(self, path, req=1, **kw):
        self.send(frame(HEADERS, END_STREAM, req, request_block(path, **kw)))
        return self.response()

    def closed(self, wait=2.0):
        self.s.settimeout(wait)
        try:
            return self.s.recv(1) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True
        except socket.timeout:
            return False

    def close(self):
        self.s.close()


# ---------------------------------------------------------------- fixtures

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_listening(port, proc):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError("bserve exited: " + proc.stderr.read().decode())
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("bserve did not start")


class Server:
    def __init__(self, root, *flags):
        self.port = free_port()
        self.proc = subprocess.Popen([BSERVE, *flags, root, str(self.port)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        wait_listening(self.port, self.proc)

    def stop(self):
        self.proc.terminate()
        self.proc.wait()


class Mock:
    """A tiny BHTTP server built from this file's own encoder. `handler(c, n)`
    is called per connection with a socket wrapper and the connection count."""

    def __init__(self, handler):
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(8)
        self.port = self.ls.getsockname()[1]
        self.connections = 0
        self.handler = handler
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                s, _ = self.ls.accept()
            except OSError:
                return
            self.connections += 1
            c = Conn.__new__(Conn)
            c.s = s
            s.settimeout(5)
            try:
                self.handler(c, self.connections)
            except Exception:
                pass
            finally:
                s.close()

    def stop(self):
        self.ls.close()


def resp_headers(status, length, extra=()):
    return block((":status", str(status)), ("content-type", "text/plain"),
                 ("content-length", str(length)), *extra)


def mock_echo_path(c, _n):
    """Answers every request with 200 and the request path as the body."""
    assert c.recv_exact(4) == PREFACE
    c.send(PREFACE)
    while True:
        try:
            ftype, flags, req, payload = c.read_frame()
        except EOFError:
            return
        if ftype == HEADERS:
            path = dict(decode_block(payload))[":path"].encode()
            c.send(frame(HEADERS, 0, req, resp_headers(200, len(path))) +
                   frame(DATA, END_STREAM, req, path))


def bcurl(*args, timeout=10):
    p = subprocess.run([BCURL, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout)
    return p.returncode, p.stdout, p.stderr


# ---------------------------------------------------------------- tests

TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


# ----- server: the happy path

@test
def server_get_index(S, W):
    c = Conn(S.port)
    r = c.get("/index.html")
    assert r["status"] == 200
    assert r["body"] == open(os.path.join(W, "index.html"), "rb").read()
    assert r["headers"]["content-length"] == str(len(r["body"]))
    assert r["headers"]["content-type"].startswith("text/html")
    assert r["req"] == 1


@test
def server_keeps_connection_open(S, W):
    c = Conn(S.port)
    for i in range(1, 21):
        assert c.get("/hello.txt", req=i)["status"] == 200
    assert not c.closed(0.3)


@test
def server_404_then_connection_still_usable(S, W):
    c = Conn(S.port)
    r = c.get("/does-not-exist.html")
    assert r["status"] == 404
    assert c.get("/index.html", req=2)["status"] == 200


@test
def server_big_binary_file_is_byte_exact_and_chunked(S, W):
    c = Conn(S.port)
    r = c.get("/big.bin")
    want = open(os.path.join(W, "big.bin"), "rb").read()
    assert r["status"] == 200 and r["body"] == want
    data_frames = [f for f in r["frames"] if f[0] == DATA]
    assert len(data_frames) > 1, "large body should span several DATA frames"
    assert all(f[3] <= 16384 for f in data_frames)
    assert all(not (f[1] & END_STREAM) for f in data_frames[:-1])


@test
def server_empty_file_ends_on_headers(S, W):
    c = Conn(S.port)
    r = c.get("/empty.txt")
    assert r["status"] == 200 and r["body"] == b""
    assert r["headers"]["content-length"] == "0"
    assert len(r["frames"]) == 1 and r["frames"][0][1] & END_STREAM


@test
def server_head(S, W):
    c = Conn(S.port)
    r = c.get("/big.bin", method="HEAD")
    assert r["status"] == 200 and r["body"] == b""
    assert r["headers"]["content-length"] == str(os.path.getsize(os.path.join(W, "big.bin")))
    assert c.get("/hello.txt", req=2)["status"] == 200  # framing still aligned


@test
def server_directory_index_and_query_string(S, W):
    c = Conn(S.port)
    assert c.get("/", req=1)["status"] == 200
    assert c.get("/docs/", req=2)["status"] == 200
    assert c.get("/docs", req=3)["status"] == 200
    assert c.get("/hello.txt?x=1#frag", req=4)["status"] == 200
    assert c.get("/hello%2Etxt", req=5)["status"] == 200


@test
def server_pipelined_requests_answered_in_order(S, W):
    c = Conn(S.port)
    c.send(b"".join(frame(HEADERS, END_STREAM, i, request_block(p))
                    for i, p in [(7, "/index.html"), (8, "/nope"), (9, "/hello.txt")]))
    rs = [c.response() for _ in range(3)]
    assert [r["req"] for r in rs] == [7, 8, 9]
    assert [r["status"] for r in rs] == [200, 404, 200]


@test
def server_handles_one_byte_at_a_time(S, W):
    c = Conn(S.port, preface=False)
    for b in PREFACE + frame(HEADERS, END_STREAM, 1, request_block("/hello.txt")):
        c.send(bytes([b]))
        time.sleep(0.002)
    assert c.recv_exact(4) == PREFACE
    assert c.response()["status"] == 200


@test
def server_concurrent_connections(S, W):
    a, b = Conn(S.port), Conn(S.port)
    assert b.get("/hello.txt")["status"] == 200
    assert a.get("/index.html")["status"] == 200


# ----- server: version-2 room (unknown things MUST be skipped)

@test
def server_skips_unknown_frame_types(S, W):
    c = Conn(S.port)
    c.send(frame(0x7F, 0x00, 0, b"x" * 1000))
    c.send(frame(0xFE, 0xFF, 1, b""))
    c.send(frame(0x02, 0x01, 1, os.urandom(100_000)))  # big, and claims END_STREAM
    assert c.get("/hello.txt")["status"] == 200


@test
def server_skips_unknown_frame_between_headers_and_data(S, W):
    c = Conn(S.port)
    c.send(frame(HEADERS, 0, 1, request_block("/hello.txt")))
    c.send(frame(0x42, 0, 1, b"ignore me"))
    c.send(frame(DATA, END_STREAM, 1, b""))
    assert c.response()["status"] == 200


@test
def server_ignores_unknown_flag_bits(S, W):
    c = Conn(S.port)
    c.send(frame(HEADERS, 0xF0 | END_STREAM, 1, request_block("/hello.txt")))
    assert c.response()["status"] == 200


@test
def server_ignores_reserved_static_index(S, W):
    c = Conn(S.port)
    blk = request_block("/hello.txt") + b"\xc8" + struct.pack(">H", 5) + b"hello"
    c.send(frame(HEADERS, END_STREAM, 1, blk))
    assert c.response()["status"] == 200


@test
def server_accepts_literal_names_even_for_table_names(S, W):
    c = Conn(S.port)
    blk = (field(":method", "GET", force_literal=True) +
           field(":path", "/hello.txt", force_literal=True) +
           field("x-anything", "goes"))
    c.send(frame(HEADERS, END_STREAM, 1, blk))
    assert c.response()["status"] == 200


@test
def server_drains_request_body(S, W):
    c = Conn(S.port)
    c.send(frame(HEADERS, 0, 1, request_block("/hello.txt")))
    c.send(frame(DATA, 0, 1, b"a" * 5000))
    c.send(frame(DATA, END_STREAM, 1, b"b" * 10))
    assert c.response()["status"] == 200
    assert c.get("/hello.txt", req=2)["status"] == 200


# ----- server: 400s that keep the connection (block bad, framing fine)

def expect_400_and_alive(port, blk, req=1):
    c = Conn(port)
    c.send(frame(HEADERS, END_STREAM, req, blk))
    r = c.response()
    assert r["status"] == 400, r["status"]
    assert c.get("/hello.txt", req=req + 1)["status"] == 200, "connection should survive"


@test
def server_400_field_overruns_block(S, W):
    expect_400_and_alive(S.port, field(":method", "GET") + b"\x02\x00\xff/abc")


@test
def server_400_truncated_literal(S, W):
    expect_400_and_alive(S.port, request_block("/") + b"\x00\x09abc")


@test
def server_400_missing_path(S, W):
    expect_400_and_alive(S.port, block((":method", "GET"), ("host", "x")))


@test
def server_400_duplicate_method(S, W):
    expect_400_and_alive(S.port, request_block("/") + field(":method", "GET"))


@test
def server_400_status_in_request(S, W):
    expect_400_and_alive(S.port, request_block("/") + field(":status", "200"))


@test
def server_400_uppercase_name(S, W):
    expect_400_and_alive(S.port, request_block("/") + field("X-Upper", "1"))


@test
def server_400_crlf_in_value(S, W):
    expect_400_and_alive(S.port, request_block("/") + field("x-evil", "a\r\nb: c"))


@test
def server_400_reserved_req_id_zero(S, W):
    c = Conn(S.port)
    c.send(frame(HEADERS, END_STREAM, 0, request_block("/hello.txt")))
    assert c.response()["status"] == 400
    assert c.get("/hello.txt", req=1)["status"] == 200


@test
def server_400_path_without_slash(S, W):
    expect_400_and_alive(S.port, request_block("hello.txt"))


@test
def server_400_bad_percent_escape(S, W):
    expect_400_and_alive(S.port, request_block("/a%zz"))
    expect_400_and_alive(S.port, request_block("/a%00b"))


@test
def server_405_with_allow(S, W):
    c = Conn(S.port)
    r = c.get("/index.html", method="DELETE")
    assert r["status"] == 405 and r["headers"]["allow"] == "GET, HEAD"


# ----- server: escaping the root

@test
def server_refuses_to_leave_root(S, W):
    c = Conn(S.port)
    for i, p in enumerate(["/../secret.txt", "/docs/../../secret.txt",
                           "/%2e%2e/secret.txt", "/escape/secret.txt"], 1):
        r = c.get(p, req=i)
        assert r["status"] in (403, 404), (p, r["status"])
        assert b"top secret" not in r["body"]


# ----- server: errors that close the connection (framing untrustworthy)

@test
def server_bad_preface_400_then_close(S, W):
    c = Conn(S.port, preface=False)
    c.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert c.recv_exact(4) == PREFACE
    r = c.response()
    assert r["status"] == 400 and r["req"] == 0
    assert c.closed()


@test
def server_unknown_major_version_505(S, W):
    c = Conn(S.port, preface=False)
    c.send(b"BH\x02\x00")
    assert c.recv_exact(4) == PREFACE
    r = c.response()
    assert r["status"] == 505 and r["req"] == 0
    assert c.closed()


@test
def server_minor_version_is_ignored(S, W):
    c = Conn(S.port, preface=False)
    c.send(b"BH\x01\x07")
    assert c.recv_exact(4) == PREFACE
    assert c.get("/hello.txt")["status"] == 200


@test
def server_data_without_request_400_close(S, W):
    c = Conn(S.port)
    c.send(frame(DATA, END_STREAM, 1, b"hi"))
    assert c.response()["status"] == 400
    assert c.closed()


@test
def server_oversized_header_block_400_close(S, W):
    c = Conn(S.port)
    c.send(struct.pack(">IBBH", 10_000_000, HEADERS, END_STREAM, 1))
    assert c.response()["status"] == 400
    assert c.closed()


@test
def server_survives_truncated_frame(S, W):
    c = Conn(S.port)
    c.send(frame(HEADERS, END_STREAM, 1, request_block("/"))[:12])
    c.close()
    assert Conn(S.port).get("/hello.txt")["status"] == 200


# ----- client: against bserve

@test
def client_get_writes_body_exit_0(S, W):
    rc, out, _ = bcurl("localhost:%d/big.bin" % S.port)
    assert rc == 0 and out == open(os.path.join(W, "big.bin"), "rb").read()


@test
def client_404_exit_nonzero(S, W):
    rc, out, err = bcurl("localhost:%d/nope" % S.port)
    assert rc == 4 and b"404" in err


@test
def client_verbose_hexdumps_every_frame(S, W):
    rc, out, err = bcurl("-v", "localhost:%d/index.html" % S.port)
    text = err.decode()
    assert rc == 0
    assert text.count(">> PREFACE") == 1 and text.count("<< PREFACE") == 1
    assert ">> HEADERS" in text and "<< HEADERS" in text and "<< DATA" in text
    assert "   header   " in text and "000000" in text


@test
def client_head(S, W):
    rc, out, _ = bcurl("-I", "localhost:%d/index.html" % S.port)
    assert rc == 0 and out == b""


@test
def client_grease_against_bserve(S, W):
    rc, out, _ = bcurl("-g", "localhost:%d/hello.txt" % S.port)
    assert rc == 0 and out == b"plain text file\n"


@test
def client_against_greasing_bserve(S, W):
    g = Server(W, "-g")
    try:
        rc, out, _ = bcurl("127.0.0.1:%d/hello.txt" % g.port, "127.0.0.1:%d/" % g.port)
        assert rc == 0 and out.startswith(b"plain text file\n")
    finally:
        g.stop()


@test
def client_custom_header_is_literal(S, W):
    rc, _, err = bcurl("-v", "-H", "X-Course: networks", "localhost:%d/" % S.port)
    assert rc == 0 and "[lit] x-course: networks" in err.decode()


@test
def client_refuses_second_host(S, W):
    rc, _, err = bcurl("localhost:%d/" % S.port, "localhost:%d/" % (S.port + 1))
    assert rc == 1 and b"second connection" in err


# ----- client: against servers that are NOT bserve

@test
def client_many_urls_one_connection(S, W):
    m = Mock(mock_echo_path)
    try:
        urls = ["127.0.0.1:%d/p%d" % (m.port, i) for i in range(5)]
        rc, out, _ = bcurl(*urls)
        assert rc == 0 and out == b"/p0/p1/p2/p3/p4"
        assert m.connections == 1, m.connections
    finally:
        m.stop()


@test
def client_skips_everything_unknown(S, W):
    body = b"tolerant reader"

    def h(c, _):
        c.recv_exact(4)
        c.read_frame()
        c.send(PREFACE + frame(0x99, 0xFF, 0, b"conn-level junk"))
        hdrs = (resp_headers(200, len(body), extra=[("x-literal", "yes")]) +
                b"\x63" + struct.pack(">H", 3) + b"???")  # reserved index 99
        c.send(frame(0x55, 0, 1, b"") + frame(HEADERS, 0xF0, 1, hdrs))
        for i, byte in enumerate(body):  # one DATA frame per byte, junk between
            c.send(frame(DATA, END_STREAM if i == len(body) - 1 else 0x80, 1, bytes([byte])))
            c.send(frame(0xA0 + i % 16, 0, 1, os.urandom(i)))
    m = Mock(h)
    try:
        rc, out, err = bcurl("127.0.0.1:%d/" % m.port)
        assert rc == 0 and out == body, (rc, out, err)
    finally:
        m.stop()


@test
def client_5xx_exit_nonzero(S, W):
    def h(c, _):
        c.recv_exact(4); c.read_frame()
        c.send(PREFACE + frame(HEADERS, END_STREAM, 1, resp_headers(503, 0)))
    m = Mock(h)
    try:
        rc, _, _ = bcurl("127.0.0.1:%d/" % m.port)
        assert rc == 5
    finally:
        m.stop()


@test
def client_rejects_non_bhttp_server(S, W):
    def h(c, _):
        c.send(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        time.sleep(0.2)
    m = Mock(h)
    try:
        rc, _, err = bcurl("127.0.0.1:%d/" % m.port)
        assert rc == 3 and b"does not speak BHTTP" in err
    finally:
        m.stop()


@test
def client_detects_short_body(S, W):
    def h(c, _):
        c.recv_exact(4); c.read_frame()
        c.send(PREFACE + frame(HEADERS, 0, 1, resp_headers(200, 10)) +
               frame(DATA, END_STREAM, 1, b"short"))
    m = Mock(h)
    try:
        rc, _, _ = bcurl("127.0.0.1:%d/" % m.port)
        assert rc == 3
    finally:
        m.stop()


@test
def client_detects_server_hangup(S, W):
    def h(c, _):
        c.recv_exact(4); c.read_frame()
        c.send(PREFACE + frame(HEADERS, 0, 1, resp_headers(200, 100)) + b"\x00\x00")
    m = Mock(h)
    try:
        rc, _, err = bcurl("127.0.0.1:%d/" % m.port)
        assert rc == 3 and b"closed" in err
    finally:
        m.stop()


# ---------------------------------------------------------------- runner

def make_root(tmp):
    w = os.path.join(tmp, "www")
    shutil.copytree(os.path.join(ROOT, "www"), w)
    random.seed(1)
    with open(os.path.join(w, "big.bin"), "wb") as f:
        f.write(bytes(random.getrandbits(8) for _ in range(1_000_003)))
    open(os.path.join(w, "empty.txt"), "wb").close()
    with open(os.path.join(tmp, "secret.txt"), "w") as f:
        f.write("top secret\n")
    os.symlink(tmp, os.path.join(w, "escape"))  # symlink pointing outside root
    return w


def main():
    if not (os.path.exists(BSERVE) and os.path.exists(BCURL)):
        sys.exit("build first: make")
    tmp = tempfile.mkdtemp()
    W = make_root(tmp)
    S = Server(W)
    failed = 0
    try:
        for t in TESTS:
            try:
                t(S, W)
                print("  ok    " + t.__name__)
            except Exception as e:
                failed += 1
                print("  FAIL  %s: %r" % (t.__name__, e))
                traceback.print_exc(limit=2)
    finally:
        S.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d/%d passed" % (len(TESTS) - failed, len(TESTS)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
