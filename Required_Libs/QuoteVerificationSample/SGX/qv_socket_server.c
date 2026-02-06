// qv_socket_server.c
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static int read_full(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t*)buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0) return 0;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 1;
}

static int write_full(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

// You must implement this by calling the same verification routine used by the sample.
// Return 0 on success, non-zero on failure; write a short ASCII message into out_msg.
int verify_quote_bytes(const uint8_t *quote, uint32_t quote_size, char *out_msg, size_t out_msg_sz);

int main(int argc, char **argv) {
    const char *sock_path = "/run/qve-verifier.sock";
    if (argc >= 2) sock_path = argv[1];

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 2; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    unlink(sock_path);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { perror("bind"); return 2; }
    if (listen(fd, 64) != 0) { perror("listen"); return 2; }

    // Make socket accessible to your user (optional)
    chmod(sock_path, 0666);

    fprintf(stderr, "QvE verifier listening on %s\n", sock_path);

    for (;;) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        uint32_t n_be = 0;
        int rr = read_full(cfd, &n_be, 4);
        if (rr <= 0) { close(cfd); continue; }
        uint32_t n = ((n_be & 0xFF) << 24) | ((n_be & 0xFF00) << 8) | ((n_be & 0xFF0000) >> 8) | ((n_be & 0xFF000000) >> 24);
        if (n == 0 || n > (8u * 1024u * 1024u)) { close(cfd); continue; }

        uint8_t *quote = (uint8_t*)malloc(n);
        if (!quote) { close(cfd); continue; }

        rr = read_full(cfd, quote, n);
        if (rr <= 0) { free(quote); close(cfd); continue; }

        char msg[512];
        memset(msg, 0, sizeof(msg));
        int vrc = verify_quote_bytes(quote, n, msg, sizeof(msg));

        free(quote);

        // Response: "OK\n" or "DENY:<reason>\n"
        if (vrc == 0) {
            write_full(cfd, "OK\n", 3);
        } else {
            const char *prefix = "DENY:";
            write_full(cfd, prefix, strlen(prefix));
            write_full(cfd, msg[0] ? msg : "verify_failed", strlen(msg[0] ? msg : "verify_failed"));
            write_full(cfd, "\n", 1);
        }
        close(cfd);
    }
}
