#define _GNU_SOURCE
#include <node_api.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#ifdef __linux__
#include "public-web-namespace.h"

static int namespace_argument(napi_env env, napi_callback_info info, char *path, size_t size) {
    size_t count = 1, length = 0;
    napi_value arg;
    if (napi_get_cb_info(env, info, &count, &arg, NULL, NULL) != napi_ok || count != 1
        || napi_get_value_string_utf8(env, arg, NULL, 0, &length) != napi_ok || length >= size
        || napi_get_value_string_utf8(env, arg, path, size, &length) != napi_ok
        || length != strlen(path) || cw_namespace_path(path) < 0) {
        napi_throw_error(env, NULL, "Invalid public web namespace"); return -1;
    }
    return 0;
}

static napi_value create_namespace(napi_env env, napi_callback_info info) {
    char path[256]; napi_value result;
    if (namespace_argument(env, info, path, sizeof(path)) < 0) return NULL;
    if (cw_create_namespace(path) < 0) {
        napi_throw_error(env, NULL, "Public web namespace creation failed"); return NULL;
    }
    napi_get_undefined(env, &result); return result;
}

static napi_value delete_namespace(napi_env env, napi_callback_info info) {
    char path[256]; napi_value result;
    if (namespace_argument(env, info, path, sizeof(path)) < 0) return NULL;
    int fd = cw_namespace_fd(path);
    if (fd < 0) { napi_throw_error(env, NULL, "Public web namespace unavailable"); return NULL; }
    close(fd);
    if (umount2(path, MNT_DETACH) < 0 || unlink(path) < 0) {
        napi_throw_error(env, NULL, "Public web namespace cleanup failed"); return NULL;
    }
    napi_get_undefined(env, &result); return result;
}

static napi_value namespace_listeners(napi_env env, napi_callback_info info) {
    char path[256]; napi_value result, value;
    if (namespace_argument(env, info, path, sizeof(path)) < 0) return NULL;
    int saved = cw_enter_namespace(path);
    if (saved < 0) { napi_throw_error(env, NULL, "Public web namespace unavailable"); return NULL; }
    int fds[4] = {-1, -1, -1, -1};
    fds[0] = cw_namespace_listener(SOCK_STREAM, "0.0.0.0", 80);
    if (fds[0] >= 0) fds[1] = cw_namespace_listener(SOCK_STREAM, "0.0.0.0", 443);
    if (fds[1] >= 0) fds[2] = cw_namespace_listener(SOCK_DGRAM, "127.0.0.1", 53);
    if (fds[2] >= 0) fds[3] = cw_namespace_listener(SOCK_STREAM, "127.0.0.1", 53);
    cw_restore_namespace(saved);
    if (fds[3] < 0 || napi_create_array_with_length(env, 4, &result) != napi_ok) goto fail;
    for (unsigned int i = 0; i < 4; i++) {
        if (napi_create_int32(env, fds[i], &value) != napi_ok
            || napi_set_element(env, result, i, value) != napi_ok) goto fail;
    }
    return result;
fail:
    for (unsigned int i = 0; i < 4; i++) if (fds[i] >= 0) close(fds[i]);
    napi_throw_error(env, NULL, "Public web namespace listeners failed"); return NULL;
}

static napi_value namespace_probe(napi_env env, napi_callback_info info) {
    char path[256]; napi_value result;
    if (namespace_argument(env, info, path, sizeof(path)) < 0) return NULL;
    int saved = cw_enter_namespace(path);
    if (saved < 0) { napi_throw_error(env, NULL, "Public web namespace unavailable"); return NULL; }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in destination = { .sin_family = AF_INET, .sin_port = htons(443) };
    inet_pton(AF_INET, "93.184.216.34", &destination.sin_addr);
    if (fd >= 0 && connect(fd, (struct sockaddr *)&destination, sizeof(destination)) < 0) { close(fd); fd = -1; }
    if (fd >= 0 && fcntl(fd, F_SETFL, O_NONBLOCK) < 0) { close(fd); fd = -1; }
    cw_restore_namespace(saved);
    if (fd < 0 || napi_create_int32(env, fd, &result) != napi_ok) {
        if (fd >= 0) close(fd);
        napi_throw_error(env, NULL, "Public web routing probe failed"); return NULL;
    }
    return result;
}

#endif

static napi_value create_pipe(napi_env env, napi_callback_info info) {
    (void)info;
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) {
        napi_throw_error(env, NULL, strerror(errno));
        return NULL;
    }
    napi_value array, reader, writer;
    if (napi_create_array_with_length(env, 2, &array) != napi_ok
        || napi_create_int32(env, fds[0], &reader) != napi_ok
        || napi_create_int32(env, fds[1], &writer) != napi_ok
        || napi_set_element(env, array, 0, reader) != napi_ok
        || napi_set_element(env, array, 1, writer) != napi_ok) {
        close(fds[0]); close(fds[1]);
        napi_throw_error(env, NULL, "cannot return anonymous pipe");
        return NULL;
    }
    return array;
}

static napi_value original_destination(napi_env env, napi_callback_info info) {
    size_t count = 1;
    napi_value args[1], result, ip, port;
    int32_t fd;
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    if (napi_get_cb_info(env, info, &count, args, NULL, NULL) != napi_ok || count != 1
        || napi_get_value_int32(env, args[0], &fd) != napi_ok || fd < 0
        || getsockname(fd, (struct sockaddr *)&address, &length) != 0
        || length != sizeof(address) || address.sin_family != AF_INET) {
        napi_throw_error(env, NULL, "original destination unavailable"); return NULL;
    }
    char text[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text))
        || napi_create_object(env, &result) != napi_ok
        || napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &ip) != napi_ok
        || napi_create_uint32(env, ntohs(address.sin_port), &port) != napi_ok
        || napi_set_named_property(env, result, "ip", ip) != napi_ok
        || napi_set_named_property(env, result, "port", port) != napi_ok) {
        napi_throw_error(env, NULL, "cannot return original destination"); return NULL;
    }
    return result;
}

/* libuv sends UDP with sendmsg, which the inherited supervisor filter denies.
 * DNS replies need only sendto; never relax descriptor-passing protection. */
static napi_value send_datagram(napi_env env, napi_callback_info info) {
    size_t count = 4, length, text_length;
    napi_value args[4], result;
    int32_t fd;
    uint32_t port;
    char text[INET_ADDRSTRLEN];
    void *bytes;
    struct sockaddr_in address = { .sin_family = AF_INET };
    if (napi_get_cb_info(env, info, &count, args, NULL, NULL) != napi_ok || count != 4
        || napi_get_value_int32(env, args[0], &fd) != napi_ok || fd < 0
        || napi_get_value_string_utf8(env, args[1], text, sizeof(text), &text_length) != napi_ok
        || text_length >= sizeof(text) || inet_pton(AF_INET, text, &address.sin_addr) != 1
        || napi_get_value_uint32(env, args[2], &port) != napi_ok || port < 1 || port > 65535
        || napi_get_buffer_info(env, args[3], &bytes, &length) != napi_ok || length > 4096) {
        napi_throw_error(env, NULL, "invalid DNS datagram"); return NULL;
    }
    address.sin_port = htons((unsigned short)port);
    if (sendto(fd, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL,
        (struct sockaddr *)&address, sizeof(address)) != (ssize_t)length) {
        napi_throw_error(env, NULL, "DNS datagram send failed"); return NULL;
    }
    napi_get_undefined(env, &result); return result;
}

static napi_value initialize(napi_env env, napi_value exports) {
    napi_value fn;
    if (napi_create_function(env, "createPipe", NAPI_AUTO_LENGTH, create_pipe, NULL, &fn) != napi_ok
        || napi_set_named_property(env, exports, "createPipe", fn) != napi_ok
        || napi_create_function(env, "originalDestination", NAPI_AUTO_LENGTH, original_destination, NULL, &fn) != napi_ok
        || napi_set_named_property(env, exports, "originalDestination", fn) != napi_ok
        || napi_create_function(env, "sendDatagram", NAPI_AUTO_LENGTH, send_datagram, NULL, &fn) != napi_ok
        || napi_set_named_property(env, exports, "sendDatagram", fn) != napi_ok) return NULL;
#ifdef __linux__
    if (napi_create_function(env, "createNetworkNamespace", NAPI_AUTO_LENGTH, create_namespace, NULL, &fn) != napi_ok
        || napi_set_named_property(env, exports, "createNetworkNamespace", fn) != napi_ok
        || napi_create_function(env, "deleteNetworkNamespace", NAPI_AUTO_LENGTH, delete_namespace, NULL, &fn) != napi_ok
        || napi_set_named_property(env, exports, "deleteNetworkNamespace", fn) != napi_ok
        || napi_create_function(env, "namespaceListeners", NAPI_AUTO_LENGTH, namespace_listeners, NULL, &fn) != napi_ok
        || napi_set_named_property(env, exports, "namespaceListeners", fn) != napi_ok
        || napi_create_function(env, "namespaceProbe", NAPI_AUTO_LENGTH, namespace_probe, NULL, &fn) != napi_ok
        || napi_set_named_property(env, exports, "namespaceProbe", fn) != napi_ok) return NULL;
#endif
    return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)
