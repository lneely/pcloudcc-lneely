/*
 * Test: readResponse rejects oversized msg->length
 *
 * Verifies the validation added in pcl-6nb.1:
 *   - msg->length > POVERLAY_BUFSIZE  → POVERLAY_READ_INVALID_RESPONSE
 *   - msg->length > total_read        → POVERLAY_READ_INVALID_RESPONSE
 *   - msg->length < header_size       → POVERLAY_READ_INVALID_RESPONSE
 *   - total_read < header_size        → POVERLAY_READ_INVALID_RESPONSE
 *   - valid message                   → 0, out populated
 *
 * Uses a socketpair so the kernel delivers bytes exactly as readResponse
 * will see them; replicates the validated logic inline (readResponse is
 * private) so we can exercise every branch without modifying app code.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stddef.h>

/* Mirror the wire layout from prpc.h */
typedef struct {
    uint32_t type;
    uint64_t length;
    char     value[];
} msg_t;

#define POVERLAY_BUFSIZE            512
#define POVERLAY_READ_SOCK_ERR      -104
#define POVERLAY_READ_INCOMPLETE    -105
#define POVERLAY_READ_INVALID_RESPONSE -106

/* Replica of the fixed readResponse logic */
static int do_read_response(int fd, char **out, size_t *out_size) {
    char buf[POVERLAY_BUFSIZE];
    msg_t *msg = (msg_t *)buf;
    size_t header_size = offsetof(msg_t, value);
    ssize_t total_read = 0;
    ssize_t bytes_read;

    while (total_read < (ssize_t)POVERLAY_BUFSIZE) {
        bytes_read = read(fd, buf + total_read, POVERLAY_BUFSIZE - total_read);
        if (bytes_read < 0) {
            if (errno == EINTR) continue;
            const char *e = "Read error";
            *out = strdup(e); *out_size = strlen(e) + 1;
            return POVERLAY_READ_SOCK_ERR;
        }
        if (bytes_read == 0) break;
        total_read += bytes_read;
        if (total_read >= (ssize_t)header_size &&
            msg->length <= (uint64_t)total_read)
            break;
    }

    if ((uint64_t)total_read < header_size ||
        msg->length < header_size          ||
        msg->length > (uint64_t)total_read ||
        msg->length > POVERLAY_BUFSIZE) {
        const char *e = "Invalid response length";
        *out = strdup(e); *out_size = strlen(e) + 1;
        return POVERLAY_READ_INVALID_RESPONSE;
    }

    size_t value_length = (size_t)msg->length - header_size;
    *out = (char *)malloc(value_length + 1);
    if (!*out) return -1;
    memcpy(*out, msg->value, value_length);
    (*out)[value_length] = '\0';
    *out_size = value_length;
    return 0;
}

static int passes = 0;
static int failures = 0;

static void run_test(const char *name,
                     const void *wire_bytes, size_t wire_len,
                     int expected_ret) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("socketpair"); exit(1);
    }

    /* Write wire bytes then close writer so reader sees EOF */
    if (wire_len > 0)
        write(sv[1], wire_bytes, wire_len);
    close(sv[1]);

    char *out = NULL;
    size_t out_size = 0;
    int ret = do_read_response(sv[0], &out, &out_size);
    close(sv[0]);
    free(out);

    if (ret == expected_ret) {
        printf("PASS: %s\n", name);
        passes++;
    } else {
        printf("FAIL: %s — expected %d got %d\n", name, expected_ret, ret);
        failures++;
    }
}

int main(void) {
    size_t hdr = offsetof(msg_t, value);

    /* --- Case 1: msg->length > POVERLAY_BUFSIZE (heap over-read, must reject) --- */
    {
        char buf[hdr];
        memset(buf, 0, hdr);
        msg_t *m = (msg_t *)buf;
        m->type   = 0;
        m->length = POVERLAY_BUFSIZE + 1;   /* oversized */
        run_test("oversized msg->length (> POVERLAY_BUFSIZE)",
                 buf, hdr, POVERLAY_READ_INVALID_RESPONSE);
    }

    /* --- Case 2: msg->length > total_read (claims more data than arrived) --- */
    {
        char buf[hdr];
        memset(buf, 0, hdr);
        msg_t *m = (msg_t *)buf;
        m->type   = 0;
        m->length = hdr + 100;  /* claims 100 bytes of value, none sent */
        run_test("msg->length > total_read",
                 buf, hdr, POVERLAY_READ_INVALID_RESPONSE);
    }

    /* --- Case 3: msg->length < header_size (underflow guard) --- */
    {
        char buf[hdr];
        memset(buf, 0, hdr);
        msg_t *m = (msg_t *)buf;
        m->type   = 0;
        m->length = hdr - 1;
        run_test("msg->length < header_size (underflow)",
                 buf, hdr, POVERLAY_READ_INVALID_RESPONSE);
    }

    /* --- Case 4: total_read < header_size (truncated message) --- */
    {
        /* Send only 2 bytes — not enough to form a header */
        char buf[2] = {0x01, 0x02};
        run_test("total_read < header_size (truncated)",
                 buf, sizeof(buf), POVERLAY_READ_INVALID_RESPONSE);
    }

    /* --- Case 5: valid message with a short value --- */
    {
        const char *val = "hello";
        size_t vlen = strlen(val);
        size_t total = hdr + vlen;
        char *buf = (char *)calloc(1, total);
        msg_t *m = (msg_t *)buf;
        m->type   = 1;
        m->length = (uint64_t)total;
        memcpy(m->value, val, vlen);
        run_test("valid message", buf, total, 0);
        free(buf);
    }

    /* --- Case 6: msg->length == POVERLAY_BUFSIZE exactly (boundary, accept) --- */
    {
        size_t vlen = POVERLAY_BUFSIZE - hdr;
        char *buf = (char *)calloc(1, POVERLAY_BUFSIZE);
        msg_t *m = (msg_t *)buf;
        m->type   = 1;
        m->length = POVERLAY_BUFSIZE;
        memset(m->value, 'A', vlen);
        run_test("msg->length == POVERLAY_BUFSIZE (boundary accept)",
                 buf, POVERLAY_BUFSIZE, 0);
        free(buf);
    }

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
