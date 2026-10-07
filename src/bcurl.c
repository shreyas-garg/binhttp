/*
 * bcurl - a BHTTP/1 client.
 *
 *   usage: bcurl [-v] [-I] [-g] [-H 'name: value']... URL [URL...]
 *
 *   URL is [bhttp://]host[:port][/path]   (port defaults to 9000)
 *
 *   -v  hexdump every frame sent and received (stderr)
 *   -I  send HEAD instead of GET
 *   -g  "grease": send an unknown frame type before every request, to prove
 *       the server skips frame types it does not know (SPEC §4)
 *   -H  add a request header (repeatable)
 *
 * Every URL is fetched over ONE TCP connection, in order. Bodies go to
 * stdout, byte for byte. Exit status:
 *   0 all 2xx/3xx   1 usage   2 cannot connect   3 protocol error
 *   4 some 4xx (no 5xx)        5 some 5xx
 */
#include "bhttp.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define DEFAULT_PORT "9000"
#define CLIENT_NAME  "bcurl/1.0"
#define GREASE_TYPE  0xBB
#define MAX_EXTRA    32
#define TIMEOUT_SECS 30

enum { EXIT_OK = 0, EXIT_USAGE = 1, EXIT_CONNECT = 2, EXIT_PROTO = 3,
       EXIT_4XX = 4, EXIT_5XX = 5 };

static FILE *g_trace;

typedef struct {
    char host[256];   /* without brackets      */
    char port[8];
    char authority[300]; /* value of the host header */
    char *path;
} url;

/* ---- URL parsing ------------------------------------------------------- */

static int parse_url(const char *s, url *u)
{
    const char *p = strstr(s, "://");
    if (p) {
        if (strncasecmp(s, "bhttp://", 8) != 0 && strncasecmp(s, "http://", 7) != 0)
            return -1;
        s = p + 3;
    }

    const char *hs, *he, *rest;
    if (*s == '[') { /* [::1]:9000 */
        hs = s + 1;
        he = strchr(hs, ']');
        if (!he)
            return -1;
        rest = he + 1;
    } else {
        hs = s;
        he = s + strcspn(s, ":/");
        rest = he;
    }
    size_t hl = (size_t)(he - hs);
    if (hl == 0 || hl >= sizeof u->host)
        return -1;
    memcpy(u->host, hs, hl);
    u->host[hl] = '\0';

    if (*rest == ':') {
        rest++;
        size_t pl = strspn(rest, "0123456789");
        if (pl == 0 || pl >= sizeof u->port)
            return -1;
        memcpy(u->port, rest, pl);
        u->port[pl] = '\0';
        long n = strtol(u->port, NULL, 10);
        if (n < 1 || n > 65535)
            return -1;
        rest += pl;
    } else {
        strcpy(u->port, DEFAULT_PORT);
    }
    if (*rest != '\0' && *rest != '/')
        return -1;

    u->path = strdup(*rest ? rest : "/");
    snprintf(u->authority, sizeof u->authority, "%s%s%s:%s",
             strchr(u->host, ':') ? "[" : "", u->host,
             strchr(u->host, ':') ? "]" : "", u->port);
    return u->path ? 0 : -1;
}

/* ---- connection -------------------------------------------------------- */

static int connect_to(const url *u)
{
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int e = getaddrinfo(u->host, u->port, &hints, &res);
    if (e) {
        fprintf(stderr, "bcurl: %s: %s\n", u->host, gai_strerror(e));
        return -1;
    }
    /* Try each address until ONE connect() succeeds. Failed attempts are
     * not connections; exactly one connection is ever established. */
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "bcurl: cannot connect to %s: %s\n", u->authority, strerror(errno));
        return -1;
    }
    struct timeval tv = { TIMEOUT_SECS, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (g_trace)
        fprintf(g_trace, "* connected to %s (one connection for all requests)\n", u->authority);
    return fd;
}

/* ---- request / response ------------------------------------------------ */

static int send_request(int fd, uint16_t id, const char *method, const url *u,
                        char **extra, int nextra, int grease)
{
    if (grease) {
        static const char junk[] = "unknown frame type: a v1 peer MUST skip this";
        if (bh_send_frame(fd, GREASE_TYPE, 0xFF, id, junk, sizeof junk - 1, g_trace) < 0)
            return -1;
    }
    bh_buf b = { 0 };
    int rc = bh_hdr_add(&b, ":method", method);
    rc |= bh_hdr_add(&b, ":path", u->path);
    rc |= bh_hdr_add(&b, "host", u->authority);
    rc |= bh_hdr_add(&b, "user-agent", CLIENT_NAME);
    rc |= bh_hdr_add(&b, "accept", "*/*");
    for (int i = 0; i < nextra; i++) {
        char *colon = strchr(extra[i], ':');
        *colon = '\0';
        const char *v = colon + 1;
        while (*v == ' ' || *v == '\t')
            v++;
        rc |= bh_hdr_add(&b, extra[i], v);
        *colon = ':';
    }
    if (rc == 0)
        rc = bh_send_frame(fd, BH_TYPE_HEADERS, BH_FLAG_END_STREAM, id,
                           b.data, (uint32_t)b.len, g_trace);
    else
        fprintf(stderr, "bcurl: request headers too large or invalid\n");
    bh_buf_free(&b);
    return rc;
}

/* Pull :status and content-length out of a response header block.
 * Returns 0 ok, -1 malformed. */
static int parse_response_headers(const uint8_t *blk, size_t len, int *status, long long *clen)
{
    size_t off = 0;
    bh_field f;
    int r, have_status = 0;
    *clen = -1;
    while ((r = bh_hdr_next(blk, len, &off, &f)) == 1) {
        if (bh_field_is(&f, ":status")) {
            if (have_status++ || f.value_len != 3 ||
                !isdigit(f.value[0]) || !isdigit(f.value[1]) || !isdigit(f.value[2]))
                return -1;
            *status = (f.value[0] - '0') * 100 + (f.value[1] - '0') * 10 + (f.value[2] - '0');
            if (*status < 100 || *status > 599)
                return -1;
        } else if (bh_field_is(&f, "content-length")) {
            if (f.value_len == 0 || f.value_len > 18)
                return -1;
            long long v = 0;
            for (size_t i = 0; i < f.value_len; i++) {
                if (!isdigit(f.value[i]))
                    return -1;
                v = v * 10 + (f.value[i] - '0');
            }
            *clen = v;
        }
    }
    return (r < 0 || !have_status) ? -1 : 0;
}

static int proto_error(const char *msg)
{
    fprintf(stderr, "bcurl: protocol error: %s\n", msg);
    return -1;
}

/* Read frames until the response to request `id` is complete.
 * Returns 0 ok, 1 ok but the server is closing the connection (it answered
 * on req_id 0), -1 protocol/transport error. */
static int read_response(int fd, uint16_t id, int head, int *status)
{
    int got_headers = 0, conn_level = 0;
    long long clen = -1, body = 0;
    uint8_t buf[BH_DATA_CHUNK];

    for (;;) {
        bh_frame_hdr h;
        uint8_t raw[BH_FRAME_HDR_LEN];
        int r = bh_recv_frame_hdr(fd, &h, raw);
        if (r <= 0)
            return proto_error(errno == EAGAIN ? "timed out waiting for response"
                                               : "connection closed mid-response");
        if (g_trace)
            bh_trace_frame_hdr(g_trace, "<<", raw);

        if (h.type != BH_TYPE_HEADERS && h.type != BH_TYPE_DATA) {
            /* §4: unknown frame type — skip it cleanly and carry on. */
            if (g_trace)
                fprintf(g_trace, "   (unknown type 0x%02x: skipping %u bytes)\n", h.type, h.length);
            if (bh_discard(fd, h.length, g_trace) < 0)
                return proto_error("connection closed inside a skipped frame");
            continue;
        }
        if (h.req_id != id && h.req_id != 0)
            return proto_error("frame for a request we did not send");
        if (h.req_id == 0)
            conn_level = 1;

        if (h.type == BH_TYPE_HEADERS) {
            if (got_headers)
                return proto_error("second HEADERS frame in one response");
            if (h.length > BH_MAX_HEADER_BLOCK)
                return proto_error("header block too large");
            uint8_t *blk = malloc(h.length ? h.length : 1);
            if (!blk || bh_read_full(fd, blk, h.length) != (long)h.length) {
                free(blk);
                return proto_error("connection closed inside HEADERS");
            }
            if (g_trace) {
                bh_trace_payload(g_trace, blk, h.length, 0);
                bh_trace_header_block(g_trace, blk, h.length);
            }
            int bad = parse_response_headers(blk, h.length, status, &clen);
            free(blk);
            if (bad)
                return proto_error("malformed response header block");
            got_headers = 1;
        } else { /* DATA */
            if (!got_headers)
                return proto_error("DATA before HEADERS");
            uint32_t left = h.length;
            size_t base = 0;
            while (left > 0) {
                size_t want = left < sizeof buf ? left : sizeof buf;
                if (bh_read_full(fd, buf, want) != (long)want)
                    return proto_error("connection closed inside DATA");
                if (g_trace)
                    bh_trace_payload(g_trace, buf, want, base);
                if (!head && fwrite(buf, 1, want, stdout) != want)
                    return proto_error("cannot write to stdout");
                left -= (uint32_t)want;
                base += want;
            }
            body += h.length;
        }
        if (h.flags & BH_FLAG_END_STREAM)
            break;
    }
    fflush(stdout);

    if (!head && clen >= 0 && body != clen) {
        fprintf(stderr, "bcurl: body was %lld bytes, content-length said %lld\n", body, clen);
        return -1;
    }
    return conn_level ? 1 : 0;
}

/* ---- main -------------------------------------------------------------- */

static void usage(void)
{
    fprintf(stderr,
        "usage: bcurl [-v] [-I] [-g] [-H 'name: value']... URL [URL...]\n"
        "  URL  [bhttp://]host[:port][/path]   (default port " DEFAULT_PORT ")\n"
        "  -v   hexdump every frame to stderr\n"
        "  -I   HEAD instead of GET\n"
        "  -g   send an unknown frame type before each request\n"
        "  -H   extra request header (repeatable)\n"
        "All URLs must share host:port; they are fetched over one connection.\n");
    exit(EXIT_USAGE);
}

int main(int argc, char **argv)
{
    int c, head = 0, grease = 0, nextra = 0;
    char *extra[MAX_EXTRA];

    while ((c = getopt(argc, argv, "vIgH:h")) != -1) {
        switch (c) {
        case 'v': g_trace = stderr; break;
        case 'I': head = 1; break;
        case 'g': grease = 1; break;
        case 'H':
            if (nextra == MAX_EXTRA || !strchr(optarg, ':') || optarg[0] == ':') {
                fprintf(stderr, "bcurl: bad -H '%s' (want 'name: value')\n", optarg);
                return EXIT_USAGE;
            }
            /* §5: names on the wire are lowercase. */
            for (char *p = optarg; *p != ':'; p++)
                *p = (char)tolower((unsigned char)*p);
            extra[nextra++] = optarg;
            break;
        default: usage();
        }
    }
    int nurls = argc - optind;
    if (nurls < 1)
        usage();
    if (nurls > 65535) {
        fprintf(stderr, "bcurl: too many URLs\n");
        return EXIT_USAGE;
    }

    url *urls = calloc((size_t)nurls, sizeof *urls);
    if (!urls)
        return EXIT_USAGE;
    for (int i = 0; i < nurls; i++) {
        if (parse_url(argv[optind + i], &urls[i]) < 0) {
            fprintf(stderr, "bcurl: bad URL '%s'\n", argv[optind + i]);
            return EXIT_USAGE;
        }
        if (i > 0 && (strcasecmp(urls[i].host, urls[0].host) != 0 ||
                      strcmp(urls[i].port, urls[0].port) != 0)) {
            fprintf(stderr, "bcurl: '%s' is on a different host:port; "
                            "bcurl never opens a second connection\n", argv[optind + i]);
            return EXIT_USAGE;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    int fd = connect_to(&urls[0]);
    if (fd < 0)
        return EXIT_CONNECT;

    /* §2: send our preface without waiting for theirs. */
    const uint8_t mine[BH_PREFACE_LEN] = { BH_MAGIC0, BH_MAGIC1, BH_VERSION_MAJOR, BH_VERSION_MINOR };
    if (g_trace)
        bh_trace_preface(g_trace, ">>", mine);
    if (bh_write_all(fd, mine, sizeof mine) < 0) {
        perror("bcurl: write");
        return EXIT_CONNECT;
    }

    int worst = EXIT_OK, got_preface = 0;
    const char *method = head ? "HEAD" : "GET";

    for (int i = 0; i < nurls; i++) {
        uint16_t id = (uint16_t)(i + 1); /* req_id 0 is reserved (§3) */
        if (send_request(fd, id, method, &urls[i], extra, nextra, grease) < 0) {
            fprintf(stderr, "bcurl: failed to send request: %s\n", strerror(errno));
            worst = EXIT_PROTO;
            break;
        }
        if (!got_preface) {
            uint8_t theirs[BH_PREFACE_LEN];
            if (bh_read_full(fd, theirs, sizeof theirs) != BH_PREFACE_LEN) {
                fprintf(stderr, "bcurl: server closed the connection before its preface\n");
                worst = EXIT_PROTO;
                break;
            }
            if (g_trace)
                bh_trace_preface(g_trace, "<<", theirs);
            if (theirs[0] != BH_MAGIC0 || theirs[1] != BH_MAGIC1) {
                fprintf(stderr, "bcurl: %s does not speak BHTTP\n", urls[0].authority);
                worst = EXIT_PROTO;
                break;
            }
            if (theirs[2] != BH_VERSION_MAJOR) {
                fprintf(stderr, "bcurl: server speaks BHTTP/%u, we speak %u\n",
                        theirs[2], BH_VERSION_MAJOR);
                worst = EXIT_PROTO;
                break;
            }
            got_preface = 1;
        }

        int status = 0;
        int r = read_response(fd, id, head, &status);
        if (r < 0) {
            worst = EXIT_PROTO;
            break;
        }
        if (g_trace)
            fprintf(g_trace, "* %s %s -> %d %s\n", method, urls[i].path, status, bh_reason(status));
        if (status >= 500) {
            fprintf(stderr, "bcurl: %s -> %d %s\n", urls[i].path, status, bh_reason(status));
            worst = EXIT_5XX;
        } else if (status >= 400) {
            fprintf(stderr, "bcurl: %s -> %d %s\n", urls[i].path, status, bh_reason(status));
            if (worst < EXIT_4XX)
                worst = EXIT_4XX;
        }
        if (r == 1)
            break; /* connection-level answer: server is hanging up */
    }

    close(fd);
    for (int i = 0; i < nurls; i++)
        free(urls[i].path);
    free(urls);
    return worst;
}
