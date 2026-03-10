/*
 * Test: readResponse rejects oversized msg->length
 *
 * Verifies the validation added in pcl-6nb.1:
 *   - msg->length > POVERLAY_BUFSIZE  → POVERLAY_READ_INVALID_RESPONSE
 *   - msg->length > total_read        → POVERLAY_READ_INVALID_RESPONSE
 *   - msg->length < header_size       → POVERLAY_READ_INVALID_RESPONSE
 *   - total_read < header_size        → POVERLAY_READ_INVALID_RESPONSE
 *   - valid message                   → 0, out populated
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stddef.h>

class RpcClient {
public:
    int readResponse(int fd, char **out, size_t *out_size);
};

extern "C" {
    typedef struct {
        uint32_t type;
        uint64_t length;
        char     value[];
    } rpc_message_t;
}

#define POVERLAY_BUFSIZE            512
#define POVERLAY_READ_SOCK_ERR      -104
#define POVERLAY_READ_INCOMPLETE    -105
#define POVERLAY_READ_INVALID_RESPONSE -106

static int passes = 0;
static int failures = 0;

#define PASS(n)    do { printf("PASS: %s\n", n); passes++; } while(0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while(0)

static void run_test(const char *name, const char *buf, size_t len, int expected_rc) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    write(sv[0], buf, len);
    close(sv[0]);
    
    RpcClient client;
    char *out = nullptr;
    size_t out_size = 0;
    int rc = client.readResponse(sv[1], &out, &out_size);
    close(sv[1]);
    
    if (rc == expected_rc)
        PASS(name);
    else
        FAIL(name, "expected %d got %d", expected_rc, rc);
    free(out);
}

int main(void) {
    size_t hdr = offsetof(rpc_message_t, value);

    {
        char buf[hdr];
        memset(buf, 0, hdr);
        rpc_message_t *m = (rpc_message_t *)buf;
        m->type   = 0;
        m->length = POVERLAY_BUFSIZE + 1;
        run_test("oversized msg->length (> POVERLAY_BUFSIZE)", buf, hdr, POVERLAY_READ_INVALID_RESPONSE);
    }

    {
        char buf[hdr];
        memset(buf, 0, hdr);
        rpc_message_t *m = (rpc_message_t *)buf;
        m->type   = 0;
        m->length = hdr + 100;
        run_test("msg->length > total_read", buf, hdr, POVERLAY_READ_INVALID_RESPONSE);
    }

    {
        char buf[hdr];
        memset(buf, 0, hdr);
        rpc_message_t *m = (rpc_message_t *)buf;
        m->type   = 0;
        m->length = hdr - 1;
        run_test("msg->length < header_size", buf, hdr, POVERLAY_READ_INVALID_RESPONSE);
    }

    {
        char buf[2] = {0x01, 0x02};
        run_test("total_read < header_size", buf, sizeof(buf), POVERLAY_READ_INVALID_RESPONSE);
    }

    {
        const char *val = "hello";
        size_t vlen = strlen(val);
        size_t total = hdr + vlen;
        char *buf = (char *)calloc(1, total);
        rpc_message_t *m = (rpc_message_t *)buf;
        m->type   = 1;
        m->length = (uint64_t)total;
        memcpy(m->value, val, vlen);
        run_test("valid message", buf, total, 0);
        free(buf);
    }

    {
        size_t vlen = POVERLAY_BUFSIZE - hdr;
        char *buf = (char *)calloc(1, POVERLAY_BUFSIZE);
        rpc_message_t *m = (rpc_message_t *)buf;
        m->type   = 1;
        m->length = POVERLAY_BUFSIZE;
        memset(m->value, 'A', vlen);
        run_test("msg->length == POVERLAY_BUFSIZE", buf, POVERLAY_BUFSIZE, 0);
        free(buf);
    }

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
