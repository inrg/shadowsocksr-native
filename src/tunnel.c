/* Copyright StrongLoop, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "common.h"
#include "tunnel.h"
#include "dump_info.h"

#if !defined(ARRAY_SIZE)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*(arr)))
#endif

static bool tunnel_is_dead(struct tunnel_ctx *tunnel);
static void tunnel_add_ref(struct tunnel_ctx *tunnel);
static void tunnel_release(struct tunnel_ctx *tunnel);
static void socket_timer_expire_cb(uv_timer_t *handle);
static void socket_timer_start(struct socket_ctx *c);
static void socket_timer_stop(struct socket_ctx *c);
static void socket_connect_done_cb(uv_connect_t *req, int status);
static void socket_read_done_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void socket_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void socket_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *ai);
static void socket_write_done_cb(uv_write_t *req, int status);
static void socket_close(struct socket_ctx *c);
static void socket_close_done_cb(uv_handle_t *handle);

int uv_stream_fd(const uv_tcp_t *handle) {
#if defined(_WIN32)
    return (int) handle->socket;
#elif defined(__APPLE__)
    int uv___stream_fd(const uv_stream_t* handle);
    return uv___stream_fd((const uv_stream_t *)handle);
#else
    return (handle)->io_watcher.fd;
#endif
}

uint16_t get_socket_port(const uv_tcp_t *tcp) {
    union sockaddr_universal tmp = { 0 };
    int len = sizeof(tmp);
    if (uv_tcp_getsockname(tcp, &tmp.addr, &len) != 0) {
        return 0;
    } else {
        return ntohs(tmp.addr4.sin_port);
    }
}

size_t _update_tcp_mss(struct socket_ctx *socket) {
#define NETWORK_MTU 1500
#define SS_TCP_MSS (NETWORK_MTU - 40)

    size_t _tcp_mss = SS_TCP_MSS;
    int fd = uv_stream_fd(&socket->handle.tcp);

    int mss = 0;
    socklen_t len = sizeof(mss);

#if defined(WIN32) || defined(_WIN32)
    getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, (char *)&mss, &len);
#else
    getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, &len);
#endif
    if (50 < mss && mss <= NETWORK_MTU) {
        _tcp_mss = (size_t) mss;
    }
    return _tcp_mss;
}

static bool tunnel_is_dead(struct tunnel_ctx *tunnel) {
    return (tunnel->terminated != false);
}

static void tunnel_add_ref(struct tunnel_ctx *tunnel) {
    tunnel->ref_count++;
}

static void tunnel_release(struct tunnel_ctx *tunnel) {
    tunnel->ref_count--;
    if (tunnel->ref_count == 0) {
        int i = 0;
        for (i = 0; i < ARRAY_SIZE(tunnel->tunnel_dying); ++i) {
            if (tunnel->tunnel_dying[i]) {
                tunnel->tunnel_dying[i](tunnel, tunnel->tunnel_dying_p[i]);
            }
        }

        free(tunnel->incoming);

        free(tunnel->outgoing);

        free(tunnel->desired_addr);

        memset(tunnel, 0, sizeof(*tunnel));
        free(tunnel);
    }
}

/* |incoming| has been initialized by listener.c when this is called. */
void tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout, tunnel_init_done_cb init_done_cb, void *p) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    struct tunnel_ctx *tunnel;
    uv_loop_t *loop = listener->loop;
    bool success = false;

    tunnel = (struct tunnel_ctx *) calloc(1, sizeof(*tunnel));

    tunnel->listener = listener;
    tunnel->ref_count = 0;
    tunnel->desired_addr = (struct socks5_address *)calloc(1, sizeof(struct socks5_address));

    incoming = (struct socket_ctx *) calloc(1, sizeof(*incoming));
    incoming->tunnel = tunnel;
    incoming->result = 0;
    incoming->rdstate = socket_stop;
    incoming->wrstate = socket_stop;
    incoming->idle_timeout = idle_timeout;
    VERIFY(0 == uv_timer_init(loop, &incoming->timer_handle));
    VERIFY(0 == uv_tcp_init(loop, &incoming->handle.tcp));
    VERIFY(0 == uv_accept((uv_stream_t *)listener, &incoming->handle.stream));
    tunnel->incoming = incoming;

    outgoing = (struct socket_ctx *) calloc(1, sizeof(*outgoing));
    outgoing->tunnel = tunnel;
    outgoing->result = 0;
    outgoing->rdstate = socket_stop;
    outgoing->wrstate = socket_stop;
    outgoing->idle_timeout = idle_timeout;
    VERIFY(0 == uv_timer_init(loop, &outgoing->timer_handle));
    VERIFY(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    tunnel->outgoing = outgoing;

    if (init_done_cb) {
        success = init_done_cb(tunnel, p);
    }

    if (success) {
        /* Wait for the initial packet. */
        socket_read(incoming, true);
    } else {
        tunnel_shutdown(tunnel);
    }
}

void tunnel_add_dying_cb(struct tunnel_ctx *tunnel, tunnel_dying_cb cb, void *p) {
    bool done = false;
    int i;
    for (i=0; i<ARRAY_SIZE(tunnel->tunnel_dying); ++i) {
        if (cb == tunnel->tunnel_dying[i]) {
            tunnel->tunnel_dying_p[i] = p;
            done = true;
            break;
        }
        if (NULL == tunnel->tunnel_dying[i]) {
            tunnel->tunnel_dying[i] = cb;
            tunnel->tunnel_dying_p[i] = p;
            done = true;
            break;
        }
    }
    ASSERT(done);
}

void tunnel_shutdown(struct tunnel_ctx *tunnel) {
    if (tunnel_is_dead(tunnel) != false) {
        return;
    }
    tunnel->terminated = true;

    /* Try to cancel the request. The callback still runs but if the
    * cancellation succeeded, it gets called with status=UV_ECANCELED.
    */
    if (tunnel->getaddrinfo_pending) {
        uv_cancel(&tunnel->outgoing->t.req);
    }

    socket_close(tunnel->incoming);
    socket_close(tunnel->outgoing);
}

//
// The logic is as follows: read when we don't write and write when we don't read.
// That gives us back-pressure handling for free because if the peer
// sends data faster than we consume it, TCP congestion control kicks in.
//
void tunnel_traditional_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *current_socket = socket;
    struct socket_ctx *target_socket = NULL;

    // 当前 网口 肯定是 入网口 或者 出网口 .
    ASSERT(current_socket == tunnel->incoming || current_socket == tunnel->outgoing);

    // 目标 网口 肯定是 当前 网口 的对立面，非此即彼 .
    target_socket = ((current_socket == tunnel->incoming) ? tunnel->outgoing : tunnel->incoming);

    // 当前 网口 的状态肯定是 写妥了 或者 读妥了，二者必居其一，但不可能同时既是读妥又是写妥 .
    ASSERT((current_socket->wrstate == socket_done && current_socket->rdstate != socket_done) ||
           (current_socket->wrstate != socket_done && current_socket->rdstate == socket_done));

    // 目标 网口 的读状态肯定不是读妥，写状态肯定不是写妥，而只可能是忙碌或者已停止 .
    ASSERT(target_socket->wrstate != socket_done && target_socket->rdstate != socket_done);

    if (current_socket->wrstate == socket_done) {
        // 如果 当前 网口 的写状态是 写妥 :
        current_socket->wrstate = socket_stop;
        if (target_socket->rdstate == socket_stop) {
            // 目标网口 的读状态如果是已停止，则开始读目标网口 .
            // 只对读取 出网口 做超时断开处理, 而对读取 入网口 不处理超时 .
            // 这很重要, 否则可能数据传输不完整即被断开 .
            socket_read(target_socket, (target_socket == tunnel->outgoing));
        }
    }
    else if (current_socket->rdstate == socket_done) {
        // 当前 网口 的读状态是 读妥 :
        current_socket->rdstate = socket_stop;

        // 目标 网口 的写状态 肯定 是 已停止, 可以再次写入了 .
        ASSERT(target_socket->wrstate == socket_stop);
        {
            size_t len = 0;
            uint8_t *buf = NULL;
            ASSERT(tunnel->tunnel_extract_data);
            buf = tunnel->tunnel_extract_data(current_socket, &malloc, &len);
            if (buf /* && size > 0 */) {
                // 从当前 网口 提取数据然后写入 目标 网口 .
                socket_write(target_socket, buf, len);
            } else {
                tunnel_shutdown(tunnel);
            }
            free(buf);
        }
    }
    else {
        ASSERT(false);
    }
}

static void socket_timer_start(struct socket_ctx *c) {
    VERIFY(0 == uv_timer_start(&c->timer_handle,
        socket_timer_expire_cb,
        c->idle_timeout,
        0));
}

static void socket_timer_stop(struct socket_ctx *c) {
    VERIFY(0 == uv_timer_stop(&c->timer_handle));
}

static void socket_timer_expire_cb(uv_timer_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(handle, struct socket_ctx, timer_handle);
    c->result = UV_ETIMEDOUT;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    if (tunnel->tunnel_timeout_expire_done) {
        tunnel->tunnel_timeout_expire_done(tunnel, c);
    }

    tunnel_shutdown(tunnel);
}

/* Assumes that c->t.sa contains a valid AF_INET or AF_INET6 address. */
int socket_connect(struct socket_ctx *c) {
    ASSERT(c->addr.addr.sa_family == AF_INET || c->addr.addr.sa_family == AF_INET6);
    socket_timer_start(c);
    return uv_tcp_connect(&c->t.connect_req,
        &c->handle.tcp,
        &c->addr.addr,
        socket_connect_done_cb);
}

static void socket_connect_done_cb(uv_connect_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, t.connect_req);
    c->result = status;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0 /*status == UV_ECANCELED || status == UV_ECONNREFUSED*/) {
        socket_dump_error_info("connect failed", c);
        tunnel_shutdown(tunnel);
        return;  /* Handle has been closed. */
    }

    ASSERT(tunnel->tunnel_outgoing_connected_done);
    tunnel->tunnel_outgoing_connected_done(tunnel, c);
}

bool socket_is_readable(struct socket_ctx *sc) {
    return sc ? (sc->rdstate == socket_stop) : false;
}

bool socket_is_writeable(struct socket_ctx *sc) {
    return sc ? (sc->wrstate == socket_stop) : false;
}

void socket_read(struct socket_ctx *c, bool check_timeout) {
    ASSERT(c->rdstate == socket_stop);
    VERIFY(0 == uv_read_start(&c->handle.stream, socket_alloc_cb, socket_read_done_cb));
    c->rdstate = socket_busy;
    if (check_timeout) {
        socket_timer_start(c);
    }
}

static void socket_read_done_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    do {
        c = CONTAINER_OF(handle, struct socket_ctx, handle);
        c->result = nread;
        tunnel = c->tunnel;

        if (tunnel_is_dead(tunnel)) {
            break;
        }

        uv_read_stop(&c->handle.stream);

        socket_timer_stop(c);

        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            // http://docs.libuv.org/en/v1.x/stream.html
            if (nread != UV_EOF) {
                socket_dump_error_info("receive data failed", c);
            }
            tunnel_shutdown(tunnel);
            break;
        }

        c->buf = buf;
        ASSERT(c->rdstate == socket_busy);
        c->rdstate = socket_done;

        ASSERT(tunnel->tunnel_read_done);
        tunnel->tunnel_read_done(tunnel, c);
    } while (0);

    if (buf->base) {
        free(buf->base); // important!!!
    }
    c->buf = NULL;
}

void socket_read_stop(struct socket_ctx *c) {
    uv_read_stop(&c->handle.stream);
    c->rdstate = socket_stop;
}

static void socket_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    struct socket_ctx *ctx;
    struct tunnel_ctx *tunnel;

    ctx = CONTAINER_OF(handle, struct socket_ctx, handle);
    tunnel = ctx->tunnel;

    ASSERT(ctx->rdstate == socket_busy);

    if (tunnel->tunnel_get_alloc_size) {
        size = tunnel->tunnel_get_alloc_size(tunnel, ctx, size);
    }

    *buf = uv_buf_init((char *)calloc(size, sizeof(char)), (unsigned int)size);
}

void socket_getaddrinfo(struct socket_ctx *c, const char *hostname) {
    struct addrinfo hints;
    struct tunnel_ctx *tunnel;
    uv_loop_t *loop;

    tunnel = c->tunnel;
    loop = tunnel->listener->loop;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    VERIFY(0 == uv_getaddrinfo(loop,
        &c->t.addrinfo_req,
        socket_getaddrinfo_done_cb,
        hostname,
        NULL,
        &hints));
    socket_timer_start(c);
    tunnel->getaddrinfo_pending = true;
}

static void socket_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *ai) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, t.addrinfo_req);
    c->result = status;

    tunnel = c->tunnel;
    tunnel->getaddrinfo_pending = false;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0) {
        socket_dump_error_info("resolve address failed", c);
        tunnel_shutdown(tunnel);
        return;
    }

    if (status == 0) {
        /* FIXME(bnoordhuis) Should try all addresses. */
        uint16_t port = c->addr.addr4.sin_port;
        if (ai->ai_family == AF_INET) {
            c->addr.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
        } else if (ai->ai_family == AF_INET6) {
            c->addr.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
        } else {
            UNREACHABLE();
        }
        c->addr.addr4.sin_port = port;
    }

    uv_freeaddrinfo(ai);

    ASSERT(tunnel->tunnel_getaddrinfo_done);
    tunnel->tunnel_getaddrinfo_done(tunnel, c);
}

void socket_write(struct socket_ctx *c, const void *data, size_t len) {
    uv_buf_t buf;
    struct tunnel_ctx *tunnel = c->tunnel;
    char *write_buf = NULL;
    uv_write_t *req;

    ASSERT(c->wrstate == socket_stop);
    c->wrstate = socket_busy;

    // It's okay to cast away constness here, uv_write() won't modify the memory.
    write_buf = (char *)calloc(len + 1, sizeof(*write_buf));
    memcpy(write_buf, data, len);
    buf = uv_buf_init(write_buf, (unsigned int)len);

    req = (uv_write_t *)calloc(1, sizeof(uv_write_t));
    req->data = write_buf;

    VERIFY(0 == uv_write(req, &c->handle.stream, &buf, 1, socket_write_done_cb));
    socket_timer_start(c);
}

static void socket_write_done_cb(uv_write_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;
    char *write_buf = NULL;

    c = CONTAINER_OF(req->handle, struct socket_ctx, handle.stream);

    VERIFY((write_buf = (char *)req->data));
    free(write_buf);

    c->result = status;
    free(req);
    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0 /*status == UV_ECANCELED*/) {
        socket_dump_error_info("send data failed", c);
        tunnel_shutdown(tunnel);
        return;  /* Handle has been closed. */
    }

    ASSERT(c->wrstate == socket_busy);
    c->wrstate = socket_done;

    ASSERT(tunnel->tunnel_write_done);
    tunnel->tunnel_write_done(tunnel, c);
}

static void socket_close(struct socket_ctx *c) {
    struct tunnel_ctx *tunnel = c->tunnel;
    ASSERT(c->rdstate != socket_dead);
    ASSERT(c->wrstate != socket_dead);
    c->rdstate = socket_dead;
    c->wrstate = socket_dead;
    c->timer_handle.data = c;
    c->handle.handle.data = c;

    tunnel_add_ref(tunnel);
    uv_close(&c->handle.handle, socket_close_done_cb);
    tunnel_add_ref(tunnel);
    uv_close((uv_handle_t *)&c->timer_handle, socket_close_done_cb);
}

static void socket_close_done_cb(uv_handle_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = (struct socket_ctx *) handle->data;
    tunnel = c->tunnel;

    tunnel_release(tunnel);
}

void socket_dump_error_info(const char *title, struct socket_ctx *socket) {
    struct tunnel_ctx *tunnel = socket->tunnel;
    int error = (int)socket->result;
    char addr[256] = { 0 };
    const char *from = NULL;
    if (socket == tunnel->outgoing) {
        socks5_address_to_string(tunnel->desired_addr, addr, sizeof(addr));
        from = "_server_";
    } else {
        union sockaddr_universal tmp = { 0 };
        int len = sizeof(tmp);
        uv_tcp_getpeername(&socket->handle.tcp, &tmp.addr, &len);
        universal_address_to_string(&tmp, addr, sizeof(addr));
        from = "_client_";
    }
    pr_err("%s about %s \"%s\": %s", title, from, addr, uv_strerror(error));
}
