#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    int fd = open("/dev/attestation/quote", O_RDONLY);
    if (fd < 0) { perror("open /dev/attestation/quote"); return 1; }

    unsigned char buf[8192];
    int n = read(fd, buf, sizeof(buf));
    if (n <= 0) { perror("read quote"); return 1; }

    printf("Read %d bytes of quote\n", n);
    return 0;
}

