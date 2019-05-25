#include <mbedtls/config.h>
#include <mbedtls/platform.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>

#include "dump_info.h"
#include "ssr_executive.h"
#include "tunnel.h"
#include "tls_cli.h"
#include "ssrbuffer.h"
#include <uv.h>
#include <uv-mbed/uv-mbed.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "ssrutils.h"

#define GET_REQUEST_FORMAT ""                                                               \
    "POST %s HTTP/1.1\r\n"                                                                  \
    "Host: %s:%d\r\n"                                                                       \
    "User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"     \
    "Accept: text/html,application/xhtml+xml,application/octet-stream;q=0.9,*/*;q=0.8\r\n"  \
    "Accept-Language: en-US,en;q=0.5\r\n"                                                   \
    "Accept-Encoding: gzip, deflate\r\n"                                                    \
    "Connection: keep-alive\r\n"                                                            \
    "Upgrade-Insecure-Requests: 1\r\n"                                                      \
    "Content-Type: application/octet-stream\r\n"                                            \
    "Content-Length: %d\r\n"                                                                \
    "\r\n"                                                                                  \

#define MAX_REQUEST_SIZE      0x8000

struct tls_cli_ctx {
    struct tunnel_ctx *tunnel; /* weak pointer */
    struct server_config *config; /* weak pointer */
    uv_mbed_t *mbed;
    bool header_parsed;
    size_t file_size;
    size_t progress_size;
};

static void tunnel_tls_send_data(struct tunnel_ctx *tunnel, const uint8_t *data, size_t size);

static void _mbed_connect_done_cb(uv_mbed_t* mbed, int status, void *p);
static void _mbed_alloc_done_cb(uv_mbed_t *mbed, size_t suggested_size, uv_buf_t *buf, void *p);
static void _mbed_data_received_cb(uv_mbed_t *mbed, ssize_t nread, uv_buf_t* buf, void *p);
static void _tls_cli_send_data(struct tls_cli_ctx *, const uint8_t *data, size_t size);
static void _mbed_write_done_cb(uv_mbed_t *mbed, int status, void *p);
static void _mbed_close_done_cb(uv_mbed_t *mbed, void *p);

void tls_client_launch(struct tunnel_ctx *tunnel, struct server_config *config) {
    uv_loop_t *loop = tunnel->listener->loop;
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)calloc(1, sizeof(*ctx));
    ctx->mbed = uv_mbed_init(loop, NULL, 0);
    ctx->config = config;
    ctx->tunnel = tunnel;

    tunnel->tls_ctx = ctx;
    tunnel->tunnel_tls_send_data = &tunnel_tls_send_data;

    uv_mbed_connect(ctx->mbed, config->remote_host, config->remote_port, _mbed_connect_done_cb, ctx);
}

void tls_client_shutdown(struct tunnel_ctx *tunnel) {
    struct tls_cli_ctx *ctx = tunnel->tls_ctx;
    uv_mbed_close(ctx->mbed, _mbed_close_done_cb, ctx);
}

static void _mbed_connect_done_cb(uv_mbed_t* mbed, int status, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    struct tunnel_ctx *tunnel = ctx->tunnel;

    if (status < 0) {
        fprintf(stderr, "connect failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close(mbed, _mbed_close_done_cb, p);
        return;
    }

    uv_mbed_read(mbed, _mbed_alloc_done_cb, _mbed_data_received_cb, p);

    if (tunnel->tunnel_tls_on_connection_established) {
        tunnel->tunnel_tls_on_connection_established(tunnel);
    }
}

static void _mbed_alloc_done_cb(uv_mbed_t *mbed, size_t suggested_size, uv_buf_t *buf, void *p) {
    char *base = (char *) calloc(suggested_size, sizeof(char));
    *buf = uv_buf_init(base, suggested_size);
}

static void _mbed_data_received_cb(uv_mbed_t *mbed, ssize_t nread, uv_buf_t* buf, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    struct tunnel_ctx *tunnel = ctx->tunnel;
    assert(ctx->mbed == mbed);
    if (nread > 0) {
        char *ptmp = (char *)buf->base;
        size_t len0 = (size_t)nread;
        if (ctx->header_parsed == false) {
#define GET_REQUEST_END "\r\n\r\n"
            char *px = strstr((char *)buf->base, GET_REQUEST_END);
            if (px != NULL) {
                ptmp = px + strlen(GET_REQUEST_END);
                len0 = len0 - (size_t)(ptmp - buf->base);
            }
            ctx->header_parsed = true;

#define CONTENT_LENGTH "Content-Length:"
            px = strstr((char *)buf->base, CONTENT_LENGTH);
            if (px) {
                px = px + strlen(CONTENT_LENGTH);
                ctx->file_size = (size_t) strtol(px, NULL, 10);
            }
        }

        assert(tunnel->tunnel_tls_on_data_received);
        if (tunnel->tunnel_tls_on_data_received) {
            tunnel->tunnel_tls_on_data_received(tunnel, (uint8_t *)ptmp, (size_t)len0);
        }
    } else if (nread < 0) {
        if (nread == UV_EOF) {
            pr_info("=====================\nconnection closed\n");
        } else {
            pr_err("read error %ld: %s\n", nread, uv_strerror((int) nread));
        }
        uv_mbed_close(mbed, _mbed_close_done_cb, p);
    }

    free(buf->base);
}

static void _tls_cli_send_data(struct tls_cli_ctx *ctx, const uint8_t *data, size_t size) {
    struct server_config *config = ctx->config;
    const char *url_path = config->over_tls_path;
    const char *domain = config->over_tls_server_domain;
    unsigned short domain_port = config->remote_port;
    uv_buf_t o;
    uint8_t *buf = (uint8_t *)calloc(MAX_REQUEST_SIZE + 1, sizeof(*buf));
    int len = mbedtls_snprintf((char *)buf, MAX_REQUEST_SIZE, GET_REQUEST_FORMAT,
        url_path, domain, domain_port, (int)size);

    if (data && size) {
        memcpy(buf + len, data, size);
        len += (int)size;
    }

    o = uv_buf_init((char *)buf, (unsigned int)len);
    uv_mbed_write(ctx->mbed, &o, &_mbed_write_done_cb, ctx);

    free(buf);
}

static void _mbed_write_done_cb(uv_mbed_t *mbed, int status, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    assert(ctx->mbed == mbed);
    if (status < 0) {
        pr_err("write failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close(mbed, _mbed_close_done_cb, p);
    } else {
        pr_info("request sent %d\n", status);
    }
}

static void _mbed_close_done_cb(uv_mbed_t *mbed, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    struct tunnel_ctx *tunnel = ctx->tunnel;
    assert(mbed == ctx->mbed);

    if (tunnel->tunnel_tls_on_shutting_down) {
        tunnel->tunnel_tls_on_shutting_down(tunnel);
    }

    uv_mbed_free(mbed);
    free(ctx);
}

static void tunnel_tls_send_data(struct tunnel_ctx *tunnel, const uint8_t *data, size_t size) {
    struct tls_cli_ctx *ctx = tunnel->tls_ctx;
    _tls_cli_send_data(ctx, data, size);
}
