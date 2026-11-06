#define _GNU_SOURCE
#include "public-web-namespace.h"

int main(int argc, char **argv) {
    if (argc < 3) return 125;
    int fd = cw_namespace_fd(argv[1]);
    if (fd < 0 || setns(fd, CLONE_NEWNET) < 0) {
        if (fd >= 0) close(fd);
        fputs("Public web namespace admission failed\n", stderr); return 125;
    }
    close(fd);
    execv(argv[2], &argv[2]);
    fputs("Public web namespace launch failed\n", stderr); return 125;
}
