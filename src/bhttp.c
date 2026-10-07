/*
 * bhttp.c - framing, header-block coding and tracing shared by
 * bserve and bcurl. See SPEC.md.
 */
#include "bhttp.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- static table (§5) ------------------------------------------------- */

static const char *const STATIC_TABLE[BH_STATIC_COUNT] = {
    NULL,              /* 0: literal */
    ":method",         /* 1 */
    ":path",           /* 2 */
    "host",            /* 3 */
    "user-agent",      /* 4 */
    "accept",          /* 5 */
    ":status",         /* 6 */
    "content-type",    /* 7 */
    "content-length",  /* 8 */
    "server",          /* 9 */
    "date",            /* 10 */
};

const char *bh_static_name(unsigned idx)
{
    return (idx > 0 && idx < BH_STATIC_COUNT) ? STATIC_TABLE[idx] : NULL;
}

unsigned bh_static_index(const char *name)
{
    for (unsigned i = 1; i < BH_STATIC_COUNT; i++)
        if (strcmp(STATIC_TABLE[i], name) == 0)
            return i;
    return 0;
}

const char *bh_type_name(uint8_t type)
{
    switch (type) {
    case BH_TYPE_DATA:    return "DATA";
    case BH_TYPE_HEADERS: return "HEADERS";
    default:              return "UNKNOWN";
    }
}

const char *bh_reason(int status)
{
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 500: return "Internal Server Error";
    case 505: return "Version Not Supported";
    default:  return "";
    }
}

/* ---- frame header (§3) ------------------------------------------------- */

void bh_put_frame_hdr(uint8_t o[BH_FRAME_HDR_LEN], const bh_frame_hdr *h)
{
    o[0] = (uint8_t)(h->length >> 24);
    o[1] = (uint8_t)(h->length >> 16);
    o[2] = (uint8_t)(h->length >> 8);
    o[3] = (uint8_t)(h->length);
    o[4] = h->type;
    o[5] = h->flags;
    o[6] = (uint8_t)(h->req_id >> 8);
    o[7] = (uint8_t)(h->req_id);
}

void bh_get_frame_hdr(const uint8_t i[BH_FRAME_HDR_LEN], bh_frame_hdr *h)
{
    h->length = ((uint32_t)i[0] << 24) | ((uint32_t)i[1] << 16) |
                ((uint32_t)i[2] << 8) | (uint32_t)i[3];
    h->type   = i[4];
    h->flags  = i[5];
    h->req_id = (uint16_t)((i[6] << 8) | i[7]);
}

/* ---- I/O --------------------------------------------------------------- */

int bh_write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

long bh_read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            break; /* EOF */
        got += (size_t)r;
    }
    return (long)got;
}

int bh_send_frame(int fd, uint8_t type, uint8_t flags, uint16_t req_id,
                  const void *payload, uint32_t len, FILE *trace)
{
    /* One buffer, one write(): avoids Nagle + delayed-ACK stalls that two
     * small writes (header, then payload) would cause. */
    uint8_t *frame = malloc(BH_FRAME_HDR_LEN + (size_t)len);
    if (!frame)
        return -1;
    bh_frame_hdr h = { len, type, flags, req_id };
    bh_put_frame_hdr(frame, &h);
    if (len)
        memcpy(frame + BH_FRAME_HDR_LEN, payload, len);

    if (trace) {
        bh_trace_frame_hdr(trace, ">>", frame);
        bh_trace_payload(trace, frame + BH_FRAME_HDR_LEN, len, 0);
        if (type == BH_TYPE_HEADERS)
            bh_trace_header_block(trace, frame + BH_FRAME_HDR_LEN, len);
    }
    int rc = bh_write_all(fd, frame, BH_FRAME_HDR_LEN + (size_t)len);
    free(frame);
    return rc;
}

int bh_recv_frame_hdr(int fd, bh_frame_hdr *h, uint8_t raw[BH_FRAME_HDR_LEN])
{
    long r = bh_read_full(fd, raw, BH_FRAME_HDR_LEN);
    if (r == 0)
        return 0;
    if (r != BH_FRAME_HDR_LEN)
        return -1;
    bh_get_frame_hdr(raw, h);
    return 1;
}

int bh_discard(int fd, uint32_t n, FILE *trace)
{
    uint8_t buf[4096];
    size_t done = 0;
    while (done < n) {
        size_t want = n - done < sizeof buf ? n - done : sizeof buf;
        long r = bh_read_full(fd, buf, want);
        if (r != (long)want)
            return -1;
        if (trace)
            bh_trace_payload(trace, buf, want, done);
        done += want;
    }
    return 0;
}

/* ---- header blocks (§5) ------------------------------------------------ */

void bh_buf_free(bh_buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static int buf_put(bh_buf *b, const void *p, size_t n)
{
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->len + n)
            cap *= 2;
        uint8_t *d = realloc(b->data, cap);
        if (!d)
            return -1;
        b->data = d;
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

int bh_hdr_add(bh_buf *b, const char *name, const char *value)
{
    size_t nlen = strlen(name), vlen = strlen(value);
    if (nlen == 0 || nlen > 255 || vlen > 0xFFFF)
        return -1;
    if (b->len + 1 + 1 + nlen + 2 + vlen > BH_MAX_HEADER_BLOCK)
        return -1;

    uint8_t idx = (uint8_t)bh_static_index(name);
    if (buf_put(b, &idx, 1) < 0)
        return -1;
    if (idx == BH_H_LITERAL) {
        uint8_t n8 = (uint8_t)nlen;
        if (buf_put(b, &n8, 1) < 0 || buf_put(b, name, nlen) < 0)
            return -1;
    }
    uint8_t v16[2] = { (uint8_t)(vlen >> 8), (uint8_t)vlen };
    if (buf_put(b, v16, 2) < 0 || buf_put(b, value, vlen) < 0)
        return -1;
    return 0;
}

/* §5: literal names are lowercase tchar, optionally with one leading ':'. */
static int valid_name(const uint8_t *s, size_t n)
{
    static const char extra[] = "!#$%&'*+-.^_`|~";
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c == ':' && i == 0 && n > 1)
            continue;
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
            continue;
        if (c != 0 && strchr(extra, c))
            continue;
        return 0;
    }
    return 1;
}

/* §5: values may not contain NUL, CR or LF (keeps a 1.1 gateway safe). */
static int valid_value(const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (s[i] == 0 || s[i] == '\r' || s[i] == '\n')
            return 0;
    return 1;
}

int bh_hdr_next(const uint8_t *blk, size_t len, size_t *off, bh_field *f)
{
    size_t o = *off;
    if (o == len)
        return 0;

    memset(f, 0, sizeof *f);
    f->index = blk[o++];

    if (f->index == BH_H_LITERAL) {
        if (o + 1 > len)
            return -1;
        f->lit_len = blk[o++];
        if (f->lit_len == 0 || o + f->lit_len > len)
            return -1;
        f->lit_name = blk + o;
        if (!valid_name(f->lit_name, f->lit_len))
            return -1;
        o += f->lit_len;
    } else {
        f->name = bh_static_name(f->index); /* NULL for reserved 11..255 */
    }

    if (o + 2 > len)
        return -1;
    f->value_len = ((size_t)blk[o] << 8) | blk[o + 1];
    o += 2;
    if (o + f->value_len > len)
        return -1;
    f->value = blk + o;
    if (!valid_value(f->value, f->value_len))
        return -1;
    o += f->value_len;

    *off = o;
    return 1;
}

int bh_field_is(const bh_field *f, const char *name)
{
    if (f->name)
        return strcmp(f->name, name) == 0;
    if (f->index == BH_H_LITERAL)
        return f->lit_len == strlen(name) &&
               memcmp(f->lit_name, name, f->lit_len) == 0;
    return 0;
}

/* ---- tracing ----------------------------------------------------------- */

void bh_trace_preface(FILE *t, const char *dir, const uint8_t p[BH_PREFACE_LEN])
{
    fprintf(t, "%s PREFACE  magic=\"%c%c\" version=%u.%u\n", dir,
            (p[0] >= 0x20 && p[0] < 0x7f) ? p[0] : '.',
            (p[1] >= 0x20 && p[1] < 0x7f) ? p[1] : '.', p[2], p[3]);
    fprintf(t, "   preface  %02x %02x %02x %02x\n", p[0], p[1], p[2], p[3]);
    fflush(t);
}

void bh_trace_frame_hdr(FILE *t, const char *dir, const uint8_t raw[BH_FRAME_HDR_LEN])
{
    bh_frame_hdr h;
    bh_get_frame_hdr(raw, &h);
    fprintf(t, "%s %-8s len=%u flags=0x%02x%s req=%u", dir, bh_type_name(h.type),
            h.length, h.flags, (h.flags & BH_FLAG_END_STREAM) ? " [END_STREAM]" : "",
            h.req_id);
    if (h.type != BH_TYPE_DATA && h.type != BH_TYPE_HEADERS)
        fprintf(t, " (type 0x%02x)", h.type);
    fprintf(t, "\n   header   ");
    for (int i = 0; i < BH_FRAME_HDR_LEN; i++)
        fprintf(t, "%02x%s", raw[i], (i == 3 || i == 5) ? " | " : " ");
    fprintf(t, "  (length | type flags | req_id)\n");
    fflush(t);
}

void bh_trace_payload(FILE *t, const uint8_t *buf, size_t n, size_t base)
{
    for (size_t row = 0; row < n; row += 16) {
        fprintf(t, "   %06zx   ", base + row);
        for (size_t i = 0; i < 16; i++) {
            if (row + i < n)
                fprintf(t, "%02x ", buf[row + i]);
            else
                fprintf(t, "   ");
            if (i == 7)
                fputc(' ', t);
        }
        fprintf(t, " |");
        for (size_t i = 0; i < 16 && row + i < n; i++) {
            uint8_t c = buf[row + i];
            fputc((c >= 0x20 && c < 0x7f) ? c : '.', t);
        }
        fprintf(t, "|\n");
    }
    fflush(t);
}

void bh_trace_header_block(FILE *t, const uint8_t *blk, size_t len)
{
    size_t off = 0;
    bh_field f;
    int r;
    while ((r = bh_hdr_next(blk, len, &off, &f)) == 1) {
        if (f.name)
            fprintf(t, "     [%2u] %s: ", f.index, f.name);
        else if (f.index == BH_H_LITERAL)
            fprintf(t, "     [lit] %.*s: ", (int)f.lit_len, (const char *)f.lit_name);
        else
            fprintf(t, "     [%2u] <reserved index, ignored>: ", f.index);
        fprintf(t, "%.*s\n", (int)f.value_len, (const char *)f.value);
    }
    if (r < 0)
        fprintf(t, "     !! malformed header block at offset %zu\n", off);
    fflush(t);
}
