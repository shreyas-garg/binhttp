/*
 * bhttp.h - BHTTP/1: HTTP semantics over a binary framing layer.
 *
 * Everything in here is defined by SPEC.md. Section numbers in comments
 * (e.g. "§3") refer to that document.
 */
#ifndef BHTTP_H
#define BHTTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* §2 Connection preface: 'B' 'H' major minor, sent by BOTH peers. */
#define BH_PREFACE_LEN     4
#define BH_MAGIC0          0x42 /* 'B' */
#define BH_MAGIC1          0x48 /* 'H' */
#define BH_VERSION_MAJOR   1
#define BH_VERSION_MINOR   0

/* §3 Frame header: length(32) type(8) flags(8) req_id(16) = 8 octets. */
#define BH_FRAME_HDR_LEN   8

/* §4 Frame types. Anything else MUST be skipped (length octets discarded). */
#define BH_TYPE_DATA       0x00
#define BH_TYPE_HEADERS    0x01

/* §3 Flags. Undefined bits MUST be ignored on receipt and sent as zero. */
#define BH_FLAG_END_STREAM 0x01

/* §6 Limits. */
#define BH_MAX_HEADER_BLOCK 65536u   /* largest HEADERS payload we accept   */
#define BH_DATA_CHUNK       16384u   /* size we split bodies into (sender)  */

/* §5 Static name table. Index 0 = literal name follows. 11..255 reserved. */
enum {
    BH_H_LITERAL        = 0,
    BH_H_METHOD         = 1,   /* :method        request  */
    BH_H_PATH           = 2,   /* :path          request  */
    BH_H_HOST           = 3,   /* host           request  */
    BH_H_USER_AGENT     = 4,   /* user-agent     request  */
    BH_H_ACCEPT         = 5,   /* accept         request  */
    BH_H_STATUS         = 6,   /* :status        response */
    BH_H_CONTENT_TYPE   = 7,   /* content-type   response */
    BH_H_CONTENT_LENGTH = 8,   /* content-length response */
    BH_H_SERVER         = 9,   /* server         response */
    BH_H_DATE           = 10,  /* date           response */
    BH_STATIC_COUNT     = 11
};

const char *bh_static_name(unsigned idx);      /* NULL if idx not in table  */
unsigned    bh_static_index(const char *name); /* 0 if name not in table    */
const char *bh_type_name(uint8_t type);        /* "DATA", "HEADERS", "UNKNOWN" */
const char *bh_reason(int status);             /* "Not Found" etc.          */

/* ---- frame header ---------------------------------------------------- */

typedef struct {
    uint32_t length;
    uint8_t  type;
    uint8_t  flags;
    uint16_t req_id;
} bh_frame_hdr;

void bh_put_frame_hdr(uint8_t out[BH_FRAME_HDR_LEN], const bh_frame_hdr *h);
void bh_get_frame_hdr(const uint8_t in[BH_FRAME_HDR_LEN], bh_frame_hdr *h);

/* ---- socket I/O -------------------------------------------------------- */

/* Write all n bytes. 0 on success, -1 on error. */
int  bh_write_all(int fd, const void *buf, size_t n);
/* Read exactly n bytes. Returns n, or fewer on EOF, or -1 on error. */
long bh_read_full(int fd, void *buf, size_t n);

/* Send a whole frame (header + payload) in a single write. 0 ok, -1 error.
 * If trace is non-NULL the frame is hexdumped to it with direction ">>". */
int  bh_send_frame(int fd, uint8_t type, uint8_t flags, uint16_t req_id,
                   const void *payload, uint32_t len, FILE *trace);

/* Read one frame header. 1 = got one, 0 = clean EOF before any byte,
 * -1 = error or EOF in the middle of the header. */
int  bh_recv_frame_hdr(int fd, bh_frame_hdr *h, uint8_t raw[BH_FRAME_HDR_LEN]);

/* Read and discard n payload bytes (used to skip unknown frames / bodies).
 * If trace is non-NULL, the discarded bytes are hexdumped. 0 ok, -1 error. */
int  bh_discard(int fd, uint32_t n, FILE *trace);

/* ---- header blocks (§5) ------------------------------------------------ */

typedef struct {
    uint8_t *data;
    size_t   len, cap;
} bh_buf;

void bh_buf_free(bh_buf *b);
/* Append one field. Uses the static index if name is in the table, else a
 * literal name. Returns 0, or -1 if name/value too long or out of memory. */
int  bh_hdr_add(bh_buf *b, const char *name, const char *value);

typedef struct {
    unsigned       index;       /* static index, or 0 for literal          */
    const char    *name;        /* static name or NULL (literal/unknown)   */
    const uint8_t *lit_name;    /* literal name bytes when index == 0      */
    size_t         lit_len;
    const uint8_t *value;
    size_t         value_len;
} bh_field;

/* Decode the next field at *off. Returns 1 = field, 0 = end of block,
 * -1 = malformed. A field with a reserved index (11..255) is returned with
 * name == NULL and index set; callers MUST ignore it (§5). */
int  bh_hdr_next(const uint8_t *blk, size_t len, size_t *off, bh_field *f);

/* True if field f has the given name (works for indexed and literal). */
int  bh_field_is(const bh_field *f, const char *name);

/* ---- tracing (-v) ------------------------------------------------------ */

void bh_trace_preface(FILE *t, const char *dir, const uint8_t p[BH_PREFACE_LEN]);
void bh_trace_frame_hdr(FILE *t, const char *dir, const uint8_t raw[BH_FRAME_HDR_LEN]);
/* Hexdump payload bytes; base is the offset of buf[0] within the payload. */
void bh_trace_payload(FILE *t, const uint8_t *buf, size_t n, size_t base);
void bh_trace_header_block(FILE *t, const uint8_t *blk, size_t len);

#endif
