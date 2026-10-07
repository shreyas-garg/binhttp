/*
 * bserve - a BHTTP/1 file server.
 *
 *   usage: bserve [-v] [-g] <root-dir> <port>
 *
 *   -v  hexdump every frame sent and received (stderr)
 *   -g  "grease": send an unknown frame type before every response, to prove
 *       that clients skip frame types they do not know (SPEC §4)
 *
 * One process per connection (fork). Each connection carries any number of
 * requests, answered in order, until the client closes it or it sits idle
 * for BH_IDLE_SECS.
 */
#include "bhttp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define BH_IDLE_SECS 60
#define SERVER_NAME  "bserve/1.0"
#define GREASE_TYPE  0xBB

static FILE  *g_trace;          /* non-NULL with -v                     */
static int    g_grease;
static char   g_root[PATH_MAX]; /* realpath of the document root        */
static size_t g_rootlen;
static char   g_peer[INET6_ADDRSTRLEN + 8];

typedef struct {
    uint16_t req_id;
    int      bad;          /* non-zero: header block was malformed        */
    char     method[32];
    char    *path;         /* malloc'd, NUL-terminated                     */
} request;

/* ---------------------------------------------------------------------- */

static const char *content_type(const char *path)
{
    static const struct { const char *ext, *type; } map[] = {
        { ".html", "text/html; charset=utf-8" },
        { ".htm",  "text/html; charset=utf-8" },
        { ".css",  "text/css; charset=utf-8" },
        { ".js",   "text/javascript; charset=utf-8" },
        { ".json", "application/json" },
        { ".txt",  "text/plain; charset=utf-8" },
        { ".md",   "text/markdown; charset=utf-8" },
        { ".svg",  "image/svg+xml" },
        { ".png",  "image/png" },
        { ".jpg",  "image/jpeg" },
        { ".jpeg", "image/jpeg" },
        { ".gif",  "image/gif" },
        { ".ico",  "image/x-icon" },
        { ".pdf",  "application/pdf" },
    };
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    if (dot && (!slash || dot > slash))
        for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
            if (strcasecmp(dot, map[i].ext) == 0)
                return map[i].type;
    return "application/octet-stream";
}

static void http_date(char *out, size_t n)
{
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(out, n, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

/* ---- sending responses ------------------------------------------------- */

static int send_grease(int fd, uint16_t req_id)
{
    static const char junk[] = "unknown frame type: a v1 peer MUST skip this";
    if (!g_grease)
        return 0;
    return bh_send_frame(fd, GREASE_TYPE, 0xFF, req_id, junk, sizeof junk - 1, g_trace);
}

/* HEADERS frame for a response. END_STREAM if no body follows. */
static int send_resp_headers(int fd, uint16_t req_id, int status, const char *ctype,
                             unsigned long long clen, const char *allow, int end)
{
    char st[8], cl[24], date[64];
    snprintf(st, sizeof st, "%d", status);
    snprintf(cl, sizeof cl, "%llu", clen);
    http_date(date, sizeof date);

    bh_buf b = { 0 };
    int rc = bh_hdr_add(&b, ":status", st);
    rc |= bh_hdr_add(&b, "content-type", ctype);
    rc |= bh_hdr_add(&b, "content-length", cl);
    rc |= bh_hdr_add(&b, "server", SERVER_NAME);
    rc |= bh_hdr_add(&b, "date", date);
    if (allow)
        rc |= bh_hdr_add(&b, "allow", allow); /* not in table: literal name */
    if (rc == 0)
        rc = send_grease(fd, req_id);
    if (rc == 0)
        rc = bh_send_frame(fd, BH_TYPE_HEADERS, end ? BH_FLAG_END_STREAM : 0,
                           req_id, b.data, (uint32_t)b.len, g_trace);
    bh_buf_free(&b);
    return rc;
}

/* A short text/plain response: used for every error status. */
static int send_simple(int fd, uint16_t req_id, int status, int head_only, const char *allow)
{
    char body[128];
    int n = snprintf(body, sizeof body, "%d %s\n", status, bh_reason(status));
    if (send_resp_headers(fd, req_id, status, "text/plain; charset=utf-8",
                          (unsigned long long)n, allow, head_only) < 0)
        return -1;
    if (head_only)
        return 0;
    return bh_send_frame(fd, BH_TYPE_DATA, BH_FLAG_END_STREAM, req_id,
                         body, (uint32_t)n, g_trace);
}

/* Returns 0 = sent fine, -1 = connection must be dropped.
 * *status_out gets the status code for the access log. */
static int send_file(int fd, uint16_t req_id, const char *path, int head_only, int *status_out)
{
    int ffd = open(path, O_RDONLY);
    if (ffd < 0) {
        *status_out = (errno == EACCES) ? 403 : 404;
        return send_simple(fd, req_id, *status_out, head_only, NULL);
    }
    struct stat st;
    if (fstat(ffd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(ffd);
        *status_out = 404;
        return send_simple(fd, req_id, 404, head_only, NULL);
    }

    *status_out = 200;
    unsigned long long remaining = (unsigned long long)st.st_size;
    int no_body = head_only || remaining == 0;
    if (send_resp_headers(fd, req_id, 200, content_type(path), remaining, NULL, no_body) < 0) {
        close(ffd);
        return -1;
    }
    if (no_body) {
        close(ffd);
        return 0;
    }

    /* Body in DATA frames of at most BH_DATA_CHUNK bytes; the last carries
     * END_STREAM. We know the size in advance, so END_STREAM is never sent
     * on an empty trailing frame. */
    uint8_t *buf = malloc(BH_DATA_CHUNK);
    int rc = buf ? 0 : -1;
    while (rc == 0 && remaining > 0) {
        size_t want = remaining < BH_DATA_CHUNK ? (size_t)remaining : BH_DATA_CHUNK;
        long got = bh_read_full(ffd, buf, want);
        if (got != (long)want) {
            /* File shrank under us. We already promised content-length, so
             * the only honest thing left is to abort the connection. */
            rc = -1;
            break;
        }
        remaining -= want;
        rc = bh_send_frame(fd, BH_TYPE_DATA, remaining ? 0 : BH_FLAG_END_STREAM,
                           req_id, buf, (uint32_t)want, g_trace);
    }
    free(buf);
    close(ffd);
    return rc;
}

/* ---- path mapping (§7) ------------------------------------------------- */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int under_root(const char *p)
{
    if (g_rootlen == 0)
        return 1; /* root is "/" */
    return strncmp(p, g_root, g_rootlen) == 0 &&
           (p[g_rootlen] == '/' || p[g_rootlen] == '\0');
}

/* Map a request :path to a file under the root. On success writes the
 * resolved path to out and returns 0; otherwise returns an HTTP status. */
static int map_path(const char *upath, char out[PATH_MAX])
{
    if (upath[0] != '/')
        return 400;

    /* Percent-decode, stopping at query or fragment. */
    size_t n = strlen(upath);
    char *dec = malloc(n + 1);
    if (!dec)
        return 500;
    size_t d = 0;
    for (size_t i = 0; i < n && upath[i] != '?' && upath[i] != '#'; i++) {
        if (upath[i] == '%') {
            int hi = i + 2 < n ? hexval(upath[i + 1]) : -1;
            int lo = i + 2 < n ? hexval(upath[i + 2]) : -1;
            if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) {
                free(dec);
                return 400;
            }
            dec[d++] = (char)(hi * 16 + lo);
            i += 2;
        } else {
            dec[d++] = upath[i];
        }
    }
    dec[d] = '\0';

    /* Refuse any ".." segment outright: cheaper and clearer than trying to
     * normalise. realpath() below also catches symlinks that escape. */
    for (char *s = dec; *s;) {
        char *e = strchr(s, '/');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if (len == 2 && s[0] == '.' && s[1] == '.') {
            free(dec);
            return 403;
        }
        s += len;
        if (*s == '/')
            s++;
    }

    char joined[PATH_MAX];
    int w = snprintf(joined, sizeof joined, "%s%s%s", g_rootlen ? g_root : "", dec,
                     dec[d ? d - 1 : 0] == '/' ? "index.html" : "");
    free(dec);
    if (w < 0 || (size_t)w >= sizeof joined)
        return 404;

    if (!realpath(joined, out))
        return errno == EACCES ? 403 : 404;
    if (!under_root(out))
        return 403;

    struct stat st;
    if (stat(out, &st) < 0)
        return 404;
    if (S_ISDIR(st.st_mode)) {
        /* "/docs" with no trailing slash: serve /docs/index.html */
        char idx[PATH_MAX];
        if ((size_t)snprintf(idx, sizeof idx, "%s/index.html", out) >= sizeof idx)
            return 404;
        if (!realpath(idx, out))
            return 404;
        if (!under_root(out) || stat(out, &st) < 0)
            return 404;
    }
    return S_ISREG(st.st_mode) ? 0 : 404;
}

/* ---- requests ---------------------------------------------------------- */

static int is_pseudo(const bh_field *f)
{
    if (f->name)
        return f->name[0] == ':';
    return f->index == BH_H_LITERAL && f->lit_name[0] == ':';
}

/* §6: a request needs exactly one :method and one :path and no other
 * pseudo-header. Regular fields are accepted and ignored. */
static void parse_request(const uint8_t *blk, size_t len, request *rq)
{
    size_t off = 0;
    bh_field f;
    int r, have_m = 0, have_p = 0;

    if (rq->req_id == 0)
        rq->bad = 1; /* req_id 0 is reserved for the connection (§3) */

    while ((r = bh_hdr_next(blk, len, &off, &f)) == 1) {
        if (f.index != BH_H_LITERAL && !f.name)
            continue; /* reserved static index: MUST ignore (§5) */
        if (bh_field_is(&f, ":method")) {
            if (have_m++ || f.value_len == 0 || f.value_len >= sizeof rq->method)
                rq->bad = 1;
            else {
                memcpy(rq->method, f.value, f.value_len);
                rq->method[f.value_len] = '\0';
            }
        } else if (bh_field_is(&f, ":path")) {
            if (have_p++ || f.value_len == 0)
                rq->bad = 1;
            else {
                free(rq->path);
                rq->path = malloc(f.value_len + 1);
                if (!rq->path) {
                    rq->bad = 1;
                    continue;
                }
                memcpy(rq->path, f.value, f.value_len);
                rq->path[f.value_len] = '\0';
            }
        } else if (is_pseudo(&f)) {
            rq->bad = 1; /* :status or unknown pseudo-header in a request */
        }
    }
    if (r < 0 || have_m != 1 || have_p != 1)
        rq->bad = 1;
}

/* Answer one complete request. Returns -1 if the connection must close. */
static int respond(int fd, request *rq)
{
    const char *m = rq->bad ? "-" : rq->method;
    const char *p = (rq->bad || !rq->path) ? "(malformed)" : rq->path;
    int status, rc;

    if (rq->bad) {
        status = 400;
        rc = send_simple(fd, rq->req_id, 400, 0, NULL);
    } else {
        int head = strcmp(rq->method, "HEAD") == 0;
        char file[PATH_MAX];
        if (!head && strcmp(rq->method, "GET") != 0) {
            status = 405;
            rc = send_simple(fd, rq->req_id, 405, 0, "GET, HEAD");
        } else if ((status = map_path(rq->path, file)) != 0) {
            rc = send_simple(fd, rq->req_id, status, head, NULL);
        } else {
            rc = send_file(fd, rq->req_id, file, head, &status);
        }
    }
    fprintf(stderr, "[%s] %s %s -> %d\n", g_peer, m, p, status);
    return rc;
}

static void reset_request(request *rq)
{
    free(rq->path);
    memset(rq, 0, sizeof *rq);
}

/* A framing-level error: the byte stream can no longer be trusted, so we
 * say 400 once and hang up (§6). */
static void fatal(int fd, uint16_t req_id, int status, const char *why)
{
    fprintf(stderr, "[%s] protocol error: %s -> %d, closing\n", g_peer, why, status);
    send_simple(fd, req_id, status, 0, NULL);
}

static void handle_connection(int fd)
{
    struct timeval tv = { BH_IDLE_SECS, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

    /* §2: both sides send the preface immediately; no round trip. */
    const uint8_t mine[BH_PREFACE_LEN] = { BH_MAGIC0, BH_MAGIC1, BH_VERSION_MAJOR, BH_VERSION_MINOR };
    if (g_trace)
        bh_trace_preface(g_trace, ">>", mine);
    if (bh_write_all(fd, mine, sizeof mine) < 0)
        return;

    uint8_t theirs[BH_PREFACE_LEN];
    if (bh_read_full(fd, theirs, sizeof theirs) != BH_PREFACE_LEN)
        return;
    if (g_trace)
        bh_trace_preface(g_trace, "<<", theirs);
    if (theirs[0] != BH_MAGIC0 || theirs[1] != BH_MAGIC1) {
        fatal(fd, 0, 400, "bad preface (not a BHTTP client)");
        return;
    }
    if (theirs[2] != BH_VERSION_MAJOR) {
        fatal(fd, 0, 505, "unsupported major version");
        return;
    }

    request rq = { 0 };
    int in_body = 0; /* got HEADERS without END_STREAM; draining DATA */
    unsigned served = 0;

    for (;;) {
        bh_frame_hdr h;
        uint8_t raw[BH_FRAME_HDR_LEN];
        int r = bh_recv_frame_hdr(fd, &h, raw);
        if (r == 0)
            break; /* client closed between frames: normal end */
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                fprintf(stderr, "[%s] idle timeout\n", g_peer);
            break;
        }
        if (g_trace)
            bh_trace_frame_hdr(g_trace, "<<", raw);

        if (h.type == BH_TYPE_HEADERS) {
            if (in_body) {
                fatal(fd, h.req_id, 400, "HEADERS while a request body is open");
                break;
            }
            if (h.length > BH_MAX_HEADER_BLOCK) {
                fatal(fd, h.req_id, 400, "header block too large");
                break;
            }
            uint8_t *blk = malloc(h.length ? h.length : 1);
            if (!blk || bh_read_full(fd, blk, h.length) != (long)h.length) {
                free(blk);
                break;
            }
            if (g_trace) {
                bh_trace_payload(g_trace, blk, h.length, 0);
                bh_trace_header_block(g_trace, blk, h.length);
            }
            reset_request(&rq);
            rq.req_id = h.req_id;
            parse_request(blk, h.length, &rq);
            free(blk);

            if (!(h.flags & BH_FLAG_END_STREAM)) {
                in_body = 1; /* answer once the body has been drained */
                continue;
            }
            if (respond(fd, &rq) < 0)
                break;
            served++;
        } else if (h.type == BH_TYPE_DATA) {
            if (!in_body || h.req_id != rq.req_id) {
                fatal(fd, h.req_id, 400, "DATA outside an open request");
                break;
            }
            /* v1 methods carry no request body; read it and drop it. */
            if (bh_discard(fd, h.length, g_trace) < 0)
                break;
            if (h.flags & BH_FLAG_END_STREAM) {
                in_body = 0;
                if (respond(fd, &rq) < 0)
                    break;
                served++;
            }
        } else {
            /* §4: unknown frame type. Skip exactly `length` octets. */
            if (g_trace)
                fprintf(g_trace, "   (unknown type 0x%02x: skipping %u bytes)\n", h.type, h.length);
            if (bh_discard(fd, h.length, g_trace) < 0)
                break;
        }
    }
    reset_request(&rq);
    fprintf(stderr, "[%s] connection closed after %u request(s)\n", g_peer, served);
}

/* ---- listening --------------------------------------------------------- */

static int listen_on(int port)
{
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    int one = 1, zero = 0;
    if (s >= 0) {
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof a6);
        a6.sin6_family = AF_INET6;
        a6.sin6_addr = in6addr_any;
        a6.sin6_port = htons((uint16_t)port);
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero); /* dual stack */
        if (bind(s, (struct sockaddr *)&a6, sizeof a6) == 0 && listen(s, 64) == 0)
            return s;
        close(s);
    }
    /* No IPv6 on this host: fall back to IPv4 only. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    struct sockaddr_in a4;
    memset(&a4, 0, sizeof a4);
    a4.sin_family = AF_INET;
    a4.sin_addr.s_addr = htonl(INADDR_ANY);
    a4.sin_port = htons((uint16_t)port);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(s, (struct sockaddr *)&a4, sizeof a4) < 0 || listen(s, 64) < 0) {
        close(s);
        return -1;
    }
    return s;
}

static void peer_name(const struct sockaddr_storage *ss, char *out, size_t n)
{
    char host[INET6_ADDRSTRLEN] = "?";
    unsigned port = 0;
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const void *)ss;
        if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr))
            inet_ntop(AF_INET, &a->sin6_addr.s6_addr[12], host, sizeof host);
        else
            inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
        port = ntohs(a->sin6_port);
    } else if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const void *)ss;
        inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
        port = ntohs(a->sin_port);
    }
    snprintf(out, n, strchr(host, ':') ? "[%s]:%u" : "%s:%u", host, port);
}

static void usage(void)
{
    fprintf(stderr, "usage: bserve [-v] [-g] <root-dir> <port>\n"
                    "  -v  hexdump every frame to stderr\n"
                    "  -g  send an unknown frame type before each response\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int c;
    while ((c = getopt(argc, argv, "vgh")) != -1) {
        switch (c) {
        case 'v': g_trace = stderr; break;
        case 'g': g_grease = 1; break;
        default:  usage();
        }
    }
    if (argc - optind != 2)
        usage();

    if (!realpath(argv[optind], g_root)) {
        perror(argv[optind]);
        return 1;
    }
    struct stat st;
    if (stat(g_root, &st) < 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "bserve: %s is not a directory\n", g_root);
        return 1;
    }
    g_rootlen = strcmp(g_root, "/") == 0 ? 0 : strlen(g_root);

    char *end;
    long port = strtol(argv[optind + 1], &end, 10);
    if (*end || port < 1 || port > 65535) {
        fprintf(stderr, "bserve: bad port '%s'\n", argv[optind + 1]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN); /* peer hung up mid-write: write() returns EPIPE */
    signal(SIGCHLD, SIG_IGN); /* children reaped automatically               */

    int ls = listen_on((int)port);
    if (ls < 0) {
        perror("bserve: listen");
        return 1;
    }
    setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(stderr, "bserve: serving %s on port %ld (BHTTP/%d.%d)\n",
            g_root, port, BH_VERSION_MAJOR, BH_VERSION_MINOR);

    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        int fd = accept(ls, (struct sockaddr *)&ss, &sl);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            perror("bserve: accept");
            continue;
        }
        pid_t pid = fork();
        if (pid == 0) {
            close(ls);
            peer_name(&ss, g_peer, sizeof g_peer);
            fprintf(stderr, "[%s] connection opened\n", g_peer);
            handle_connection(fd);
            close(fd);
            _exit(0);
        }
        if (pid < 0)
            perror("bserve: fork");
        close(fd);
    }
}
