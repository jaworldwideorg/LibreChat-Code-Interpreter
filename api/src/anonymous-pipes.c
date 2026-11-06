#define _GNU_SOURCE
#include <node_api.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

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
        || getsockopt(fd, SOL_IP, 80 /* SO_ORIGINAL_DST */, &address, &length) != 0
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
    return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)
