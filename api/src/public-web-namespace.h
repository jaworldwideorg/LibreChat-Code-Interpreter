#ifndef CODEAPI_PUBLIC_WEB_NAMESPACE_H
#define CODEAPI_PUBLIC_WEB_NAMESPACE_H
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/nsfs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

/* Only root-owned lease paths may select a namespace. No user request or
 * environment value supplies these paths. Validate again at the native edge. */
static inline int cw_namespace_path(const char *path) {
    const char *prefix = "/tmp/codeapi-network-";
    if (geteuid() != 0 || strncmp(path, prefix, strlen(prefix)) != 0) {
        errno = EPERM; return -1;
    }
    const char *cursor = path + strlen(prefix);
    const char *first = cursor;
    while (*cursor >= '0' && *cursor <= '9') cursor++;
    if (cursor == first || strcmp(cursor, "/netns") != 0 || strlen(path) >= 256) {
        errno = EINVAL; return -1;
    }
    char directory[256];
    size_t length = (size_t)(cursor - path);
    memcpy(directory, path, length); directory[length] = 0;
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat status;
    if (fd < 0) return -1;
    int result = fstat(fd, &status);
    if (result == 0 && (status.st_uid != 0 || (status.st_mode & 0022))) {
        errno = EPERM; result = -1;
    }
    int saved = errno; close(fd); errno = saved; return result;
}

static inline int cw_namespace_fd(const char *path) {
    if (cw_namespace_path(path) < 0) return -1;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat status;
    if (fd < 0) return -1;
    if (fstat(fd, &status) < 0 || status.st_uid != 0
        || ioctl(fd, NS_GET_NSTYPE) != CLONE_NEWNET) {
        int saved = errno ? errno : EPERM; close(fd); errno = saved; return -1;
    }
    return fd;
}

static inline int cw_enter_namespace(const char *path) {
    int target = cw_namespace_fd(path);
    if (target < 0) return -1;
    int saved = open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
    if (saved < 0 || setns(target, CLONE_NEWNET) < 0) {
        int error = errno; close(target); if (saved >= 0) close(saved);
        errno = error; return -1;
    }
    close(target); return saved;
}

static inline void cw_restore_namespace(int saved) {
    /* Continuing in the wrong namespace is never a recovery path. */
    if (setns(saved, CLONE_NEWNET) < 0) abort();
    close(saved);
}

static inline int cw_local_routes(void) {
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (control < 0) return -1;
    struct ifreq interface = {0};
    strcpy(interface.ifr_name, "lo"); interface.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(control, SIOCSIFFLAGS, &interface) < 0
        || ioctl(control, SIOCGIFINDEX, &interface) < 0) {
        int error = errno; close(control); errno = error; return -1;
    }
    close(control);
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct timeval timeout = { .tv_sec = 2 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        int error = errno; close(fd); errno = error; return -1;
    }
    struct { struct nlmsghdr header; struct rtmsg route; struct rtattr attr; int index; } message = {0};
    message.header.nlmsg_len = sizeof(message);
    message.header.nlmsg_type = RTM_NEWROUTE;
    message.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    message.header.nlmsg_seq = 1;
    message.route.rtm_family = AF_INET;
    message.route.rtm_table = RT_TABLE_LOCAL;
    message.route.rtm_protocol = RTPROT_STATIC;
    message.route.rtm_scope = RT_SCOPE_HOST;
    message.route.rtm_type = RTN_LOCAL;
    message.attr.rta_len = RTA_LENGTH(sizeof(int));
    message.attr.rta_type = RTA_OIF;
    message.index = interface.ifr_ifindex;
    struct sockaddr_nl destination = { .nl_family = AF_NETLINK };
    int result = -1;
    if (sendto(fd, &message, sizeof(message), 0, (struct sockaddr *)&destination,
            sizeof(destination)) == (ssize_t)sizeof(message)) {
        union { struct nlmsghdr alignment; char bytes[4096]; } reply;
        ssize_t length = recv(fd, reply.bytes, sizeof(reply.bytes), 0);
        struct nlmsghdr *header = (struct nlmsghdr *)reply.bytes;
        if (length >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))
            && header->nlmsg_type == NLMSG_ERROR && header->nlmsg_seq == 1
            && header->nlmsg_len <= (size_t)length) {
            struct nlmsgerr *error = NLMSG_DATA(header);
            if (!error->error) result = 0;
            else errno = -error->error;
        } else if (length >= 0) errno = EPROTO;
    }
    int error = errno; close(fd); errno = error; return result;
}

static inline int cw_create_namespace(const char *path) {
    if (cw_namespace_path(path) < 0) return -1;
    int file = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file < 0) return -1;
    close(file);
    int saved = open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
    if (saved < 0) { int error = errno; unlink(path); errno = error; return -1; }
    if (unshare(CLONE_NEWNET) < 0) {
        int error = errno; close(saved); unlink(path); errno = error; return -1;
    }
    int result = cw_local_routes();
    if (result == 0) result = mount("/proc/thread-self/ns/net", path, NULL, MS_BIND, NULL);
    int error = errno;
    cw_restore_namespace(saved);
    if (result < 0) unlink(path);
    errno = error; return result;
}

static inline int cw_namespace_listener(int type, const char *ip, unsigned short port) {
    int fd = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1
        || bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0
        || (type == SOCK_STREAM && listen(fd, 16) < 0)) {
        int error = errno; close(fd); errno = error; return -1;
    }
    return fd;
}
#endif
