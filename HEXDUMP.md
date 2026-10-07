# Annotated hexdump: one complete request and response

Captured from a real run (the raw `-v` trace is in [docs/capture-raw.txt](docs/capture-raw.txt)):

```
$ ./bserve ./www 9000 &
$ ./bcurl -v localhost:9000/index.html
```

The tables below were made by [tools/annotate.py](tools/annotate.py). It rebuilds both byte streams from the trace and decodes them using only the rules in SPEC.md. It raises an error if it meets a byte the spec can't explain. To regenerate them:

```
python3 tools/annotate.py docs/capture-raw.txt          # tables below
python3 tools/annotate.py docs/capture-raw.txt --xxd    # plain dump
```

## A. The raw bytes, exactly as they crossed the wire

```
CLIENT -> SERVER  (67 bytes)
00000000: 42 48 01 00 00 00 00 37 01 01 00 01 01 00 03 47  BH.....7.......G
00000010: 45 54 02 00 0b 2f 69 6e 64 65 78 2e 68 74 6d 6c  ET.../index.html
00000020: 03 00 0e 6c 6f 63 61 6c 68 6f 73 74 3a 39 30 30  ...localhost:900
00000030: 30 04 00 09 62 63 75 72 6c 2f 31 2e 30 05 00 03  0...bcurl/1.0...
00000040: 2a 2f 2a                                         */*

SERVER -> CLIENT  (237 bytes)
00000000: 42 48 01 00 00 00 00 54 01 00 00 01 06 00 03 32  BH.....T.......2
00000010: 30 30 07 00 18 74 65 78 74 2f 68 74 6d 6c 3b 20  00...text/html; 
00000020: 63 68 61 72 73 65 74 3d 75 74 66 2d 38 08 00 03  charset=utf-8...
00000030: 31 33 33 09 00 0a 62 73 65 72 76 65 2f 31 2e 30  133...bserve/1.0
00000040: 0a 00 1d 54 75 65 2c 20 30 36 20 4f 63 74 20 32  ...Tue, 06 Oct 2
00000050: 30 32 36 20 31 33 3a 30 37 3a 34 39 20 47 4d 54  026 13:07:49 GMT
00000060: 00 00 00 85 00 01 00 01 3c 21 64 6f 63 74 79 70  ........<!doctyp
00000070: 65 20 68 74 6d 6c 3e 0a 3c 68 74 6d 6c 3e 0a 3c  e html>.<html>.<
00000080: 68 65 61 64 3e 3c 74 69 74 6c 65 3e 42 48 54 54  head><title>BHTT
00000090: 50 3c 2f 74 69 74 6c 65 3e 3c 2f 68 65 61 64 3e  P</title></head>
000000a0: 0a 3c 62 6f 64 79 3e 0a 3c 68 31 3e 48 65 6c 6c  .<body>.<h1>Hell
000000b0: 6f 20 6f 76 65 72 20 42 48 54 54 50 2f 31 3c 2f  o over BHTTP/1</
000000c0: 68 31 3e 0a 3c 70 3e 53 65 72 76 65 64 20 62 79  h1>.<p>Served by
000000d0: 20 62 73 65 72 76 65 2e 3c 2f 70 3e 0a 3c 2f 62   bserve.</p>.</b
000000e0: 6f 64 79 3e 0a 3c 2f 68 74 6d 6c 3e 0a           ody>.</html>.
```

The two directions are independent byte streams. The client sends its preface and its request together, without waiting for the server's preface (SPEC §2). So the client's 67 bytes go out in one burst and the server answers with 237.

## B. Every byte, field by field

```
CLIENT -> SERVER  (67 bytes on the wire)

off   bytes                                field           meaning
----  -----------------------------------  --------------  ------------------------------------
0000  42 48                                preface.magic   "BH": this is BHTTP
0002  01                                   preface.major   major version 1: must match
0003  00                                   preface.minor   minor version 0: ignored

0004  00 00 00 37                          frame.length    55 payload octets follow
0008  01                                   frame.type      0x01 = HEADERS
0009  01                                   frame.flags     0x01 = END_STREAM: message ends here
000a  00 01                                frame.req_id    request 1
000c  01                                   f1.index        1 = :method (static table)
000d  00 03                                f1.value_len    3
000f  47 45 54                             f1.value        "GET"
0012  02                                   f2.index        2 = :path (static table)
0013  00 0b                                f2.value_len    11
0015  2f 69 6e 64 65 78 2e 68 74 6d 6c     f2.value        "/index.html"
0020  03                                   f3.index        3 = host (static table)
0021  00 0e                                f3.value_len    14
0023  6c 6f 63 61 6c 68 6f 73 74 3a 39 30  f3.value        "localhost:90"
002f  30 30                                                "00"
0031  04                                   f4.index        4 = user-agent (static table)
0032  00 09                                f4.value_len    9
0034  62 63 75 72 6c 2f 31 2e 30           f4.value        "bcurl/1.0"
003d  05                                   f5.index        5 = accept (static table)
003e  00 03                                f5.value_len    3
0040  2a 2f 2a                             f5.value        "*/*"

SERVER -> CLIENT  (237 bytes on the wire)

off   bytes                                field           meaning
----  -----------------------------------  --------------  ------------------------------------
0000  42 48                                preface.magic   "BH": this is BHTTP
0002  01                                   preface.major   major version 1: must match
0003  00                                   preface.minor   minor version 0: ignored

0004  00 00 00 54                          frame.length    84 payload octets follow
0008  01                                   frame.type      0x01 = HEADERS
0009  00                                   frame.flags     0x00 = none: more frames follow
000a  00 01                                frame.req_id    request 1
000c  06                                   f1.index        6 = :status (static table)
000d  00 03                                f1.value_len    3
000f  32 30 30                             f1.value        "200"
0012  07                                   f2.index        7 = content-type (static table)
0013  00 18                                f2.value_len    24
0015  74 65 78 74 2f 68 74 6d 6c 3b 20 63  f2.value        "text/html; c"
0021  68 61 72 73 65 74 3d 75 74 66 2d 38                  "harset=utf-8"
002d  08                                   f3.index        8 = content-length (static table)
002e  00 03                                f3.value_len    3
0030  31 33 33                             f3.value        "133"
0033  09                                   f4.index        9 = server (static table)
0034  00 0a                                f4.value_len    10
0036  62 73 65 72 76 65 2f 31 2e 30        f4.value        "bserve/1.0"
0040  0a                                   f5.index        10 = date (static table)
0041  00 1d                                f5.value_len    29
0043  54 75 65 2c 20 30 36 20 4f 63 74 20  f5.value        "Tue, 06 Oct "
004f  32 30 32 36 20 31 33 3a 30 37 3a 34                  "2026 13:07:4"
005b  39 20 47 4d 54                                       "9 GMT"

0060  00 00 00 85                          frame.length    133 payload octets follow
0064  00                                   frame.type      0x00 = DATA
0065  01                                   frame.flags     0x01 = END_STREAM: message ends here
0066  00 01                                frame.req_id    request 1
0068  3c 21 64 6f 63 74 79 70 65 20 68 74  body            "<!doctype ht"
0074  6d 6c 3e 0a 3c 68 74 6d 6c 3e 0a 3c                  "ml>.<html>.<"
0080  68 65 61 64 3e 3c 74 69 74 6c 65 3e                  "head><title>"
008c  42 48 54 54 50 3c 2f 74 69 74 6c 65                  "BHTTP</title"
0098  3e 3c 2f 68 65 61 64 3e 0a 3c 62 6f                  "></head>.<bo"
00a4  64 79 3e 0a 3c 68 31 3e 48 65 6c 6c                  "dy>.<h1>Hell"
00b0  6f 20 6f 76 65 72 20 42 48 54 54 50                  "o over BHTTP"
00bc  2f 31 3c 2f 68 31 3e 0a 3c 70 3e 53                  "/1</h1>.<p>S"
00c8  65 72 76 65 64 20 62 79 20 62 73 65                  "erved by bse"
00d4  72 76 65 2e 3c 2f 70 3e 0a 3c 2f 62                  "rve.</p>.</b"
00e0  6f 64 79 3e 0a 3c 2f 68 74 6d 6c 3e                  "ody>.</html>"
00ec  0a                                                   "."
```

## C. Reading the exchange

1. **Preface, both directions (`42 48 01 00`).** Each side announces "BH", version 1.0. If the client had been a plain HTTP/1.1 client, its first bytes would be `47 45 54 20` ("GET "). The server would reply `400` on req_id 0 and close (tested in `server_bad_preface_400_then_close`).
2. **Request frame header (`00 00 00 37 | 01 | 01 | 00 01`).** 55 bytes of payload, type HEADERS, flags END_STREAM, request 1. END_STREAM sits on the HEADERS frame because a GET has no body, so the whole request is one frame.
3. **Request header block.** Five fields, each `index, 2-byte length, value`. Every name is in the static table, so no name is spelled out: `:method` costs 1 byte instead of 7 and `user-agent` costs 1 instead of 10. The block is 55 bytes. The same request in HTTP/1.1 text is 86 bytes.
4. **Response HEADERS (`00 00 00 54 | 01 | 00 | 00 01`).** 84 bytes, flags **0**, request 1. END_STREAM is *not* set because a body follows. The req_id `00 01` echoes the request, so the client checks that this response belongs to it.
5. **Response header block.** `:status` is index 6, value `"200"` as three ASCII digits. `content-length` is `"133"`, which the client compares against the DATA it receives.
6. **DATA (`00 00 00 85 | 00 | 01 | 00 01`).** 133 bytes of body (0x85 = 133), with END_STREAM. The response is complete, and the connection stays open for another request.

**Totals.** Request: 4 preface + 8 header + 55 block = 67 bytes. Response: 4 preface + (8 + 84) + (8 + 133) = 237 bytes. Framing overhead on the response is 16 bytes, two frame headers.

## D. Appendix: the two things that example didn't show

Captured with `./bserve -g ./www 9000` and `./bcurl -v -H "X-Course: networks" localhost:9000/hello.txt` (raw trace in [docs/capture-literal-grease.txt](docs/capture-literal-grease.txt)).

**A literal-name field.** `x-course` is not one of the ten table names, so it uses index 0, a 1-byte name length and the name, then the usual 2-byte value length and value. bcurl lowercased the name, as SPEC §5 requires. These are the last 20 bytes of the request header block:

```
off   bytes                                field           meaning
----  -----------------------------------  --------------  ------------------------------------
0042  00                                   f6.index        0 = literal name follows
0043  08                                   f6.name_len     8
0044  78 2d 63 6f 75 72 73 65              f6.name         "x-course"
004c  00 08                                f6.value_len    8
004e  6e 65 74 77 6f 72 6b 73              f6.value        "networks"
```

**An unknown frame, skipped.** The `-g` server sends frame type `0xbb` (flags `0xff`) before its response. The client reads the 8-byte header, sees a type it doesn't know, discards exactly `0x2c` = 44 payload bytes and goes on to the HEADERS frame at offset `0x38`. Nothing else is needed to stay in sync, and this is how a version 2 can add frame types without breaking version 1 peers.

```
off   bytes                                field           meaning
----  -----------------------------------  --------------  ------------------------------------
0004  00 00 00 2c                          frame.length    44 payload octets follow
0008  bb                                   frame.type      0xbb = unknown: skip
0009  ff                                   frame.flags     0xff = meaningless on an unknown type
000a  00 01                                frame.req_id    request 1
000c  75 6e 6b 6e 6f 77 6e 20 66 72 61 6d  skipped         "unknown fram"
0018  65 20 74 79 70 65 3a 20 61 20 76 31                  "e type: a v1"
0024  20 70 65 65 72 20 4d 55 53 54 20 73                  " peer MUST s"
0030  6b 69 70 20 74 68 69 73                              "kip this"

0038  00 00 00 54                          frame.length    84 payload octets follow
```
