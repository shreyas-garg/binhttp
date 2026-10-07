#!/usr/bin/env python3
"""
annotate.py - turn a `bcurl -v` trace into a field-by-field annotated
hexdump of both byte streams, using only the rules in SPEC.md.

    ./bcurl -v localhost:9000/index.html 2> trace.txt >/dev/null
    python3 tools/annotate.py trace.txt          # annotated tables
    python3 tools/annotate.py trace.txt --xxd    # plain wire dump

If a byte cannot be explained by the spec, this script raises.
"""
import re
import struct
import sys

STATIC = [None, ":method", ":path", "host", "user-agent", "accept",
          ":status", "content-type", "content-length", "server", "date"]
TYPES = {0x00: "DATA", 0x01: "HEADERS"}
ROW = re.compile(r"^   [0-9a-f]{6}   ")  # payload row: offset, then 16 hex columns
WRAP = 12  # bytes per row in the annotated table


def streams_from_trace(path):
    """Rebuild the exact client->server and server->client byte streams."""
    out = {">>": bytearray(), "<<": bytearray()}
    direction = None
    for line in open(path):
        if line.startswith((">>", "<<")):
            direction = line[:2]
        elif direction:
            # columns are fixed by bh_trace_*() in src/bhttp.c
            if line.startswith("   preface  "):
                hexpart = line[12:]
            elif line.startswith("   header   "):
                hexpart = line[12:].split("(")[0].replace("|", " ")
            elif ROW.match(line):
                hexpart = line[12:61]
            else:
                continue
            out[direction] += bytes(int(h, 16) for h in hexpart.split())
    return bytes(out[">>"]), bytes(out["<<"])


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


class Annotator:
    def __init__(self, data):
        self.d, self.o, self.rows = data, 0, []

    def peek(self, n):
        chunk = self.d[self.o:self.o + n]
        if len(chunk) != n:
            raise ValueError("stream ends at %d, wanted %d more bytes" % (self.o, n))
        return chunk

    def emit(self, n, field, meaning, text=False):
        chunk = self.peek(n)
        for i in range(0, max(n, 1), WRAP):
            part = chunk[i:i + WRAP]
            m = meaning if i == 0 else ('"%s"' % printable(part) if text else "")
            self.rows.append(("%04x" % (self.o + i), " ".join("%02x" % c for c in part),
                              field if i == 0 else "", m))
        self.o += n
        return chunk

    def u8(self):
        return self.peek(1)[0]

    def u16(self):
        return struct.unpack(">H", self.peek(2))[0]

    def u32(self):
        return struct.unpack(">I", self.peek(4))[0]

    def preface(self):
        self.emit(2, "preface.magic", '"BH": this is BHTTP')
        self.emit(1, "preface.major", "major version %d: must match" % self.u8())
        self.emit(1, "preface.minor", "minor version %d: ignored" % self.u8())

    def frame(self):
        self.rows.append(("", "", "", ""))
        length = self.u32()
        self.emit(4, "frame.length", "%d payload octets follow" % length)
        ftype = self.u8()
        self.emit(1, "frame.type", "0x%02x = %s" % (ftype, TYPES.get(ftype, "unknown: skip")))
        flags = self.u8()
        if ftype not in TYPES:
            fl = "meaningless on an unknown type"
        elif flags & 1:
            fl = "END_STREAM: message ends here"
        else:
            fl = "none: more frames follow"
        if ftype in TYPES and flags & 0xFE:
            fl += " (+ undefined bits: ignore)"
        self.emit(1, "frame.flags", "0x%02x = %s" % (flags, fl))
        self.emit(2, "frame.req_id", "request %d" % self.u16())
        end = self.o + length

        if ftype == 0x01:
            n = 0
            while self.o < end:
                n += 1
                idx = self.u8()
                if idx == 0:
                    self.emit(1, "f%d.index" % n, "0 = literal name follows")
                    nl = self.u8()
                    self.emit(1, "f%d.name_len" % n, "%d" % nl)
                    self.emit(nl, "f%d.name" % n, '"%s"' % printable(self.peek(nl)[:WRAP]), True)
                elif idx < len(STATIC):
                    self.emit(1, "f%d.index" % n, "%d = %s (static table)" % (idx, STATIC[idx]))
                else:
                    self.emit(1, "f%d.index" % n, "%d = reserved: ignore field" % idx)
                vl = self.u16()
                self.emit(2, "f%d.value_len" % n, "%d" % vl)
                self.emit(vl, "f%d.value" % n, '"%s"' % printable(self.peek(vl)[:WRAP]), True)
            if self.o != end:
                raise ValueError("header block overran its frame")
        else:
            name = "body" if ftype == 0x00 else "skipped"
            self.emit(length, name, '"%s"' % printable(self.peek(length)[:WRAP]), True)

    def run(self):
        self.preface()
        while self.o < len(self.d):
            self.frame()
        return self.rows


def table(title, data):
    print("%s  (%d bytes on the wire)\n" % (title, len(data)))
    print("off   %-35s  %-14s  meaning" % ("bytes", "field"))
    print("----  %s  %s  %s" % ("-" * 35, "-" * 14, "-" * 36))
    for off, b, f, m in Annotator(data).run():
        print(("%-4s  %-35s  %-14s  %s" % (off, b, f, m)).rstrip())
    print()


def xxd(title, data):
    print("%s  (%d bytes)" % (title, len(data)))
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        print("%08x: %-47s  %s" % (i, " ".join("%02x" % c for c in row), printable(row)))
    print()


if __name__ == "__main__":
    c2s, s2c = streams_from_trace(sys.argv[1])
    show = xxd if "--xxd" in sys.argv else table
    show("CLIENT -> SERVER", c2s)
    show("SERVER -> CLIENT", s2c)
