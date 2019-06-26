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

struct tls_cli_ctx {
    struct tunnel_ctx *tunnel; /* weak pointer */
    struct server_config *config; /* weak pointer */
    uv_mbed_t *mbed;
};

static void tunnel_tls_send_data(struct tunnel_ctx *tunnel, const uint8_t *data, size_t size);
static void tunnel_dying(struct tunnel_ctx *tunnel, void *p);

static void _mbed_connect_done_cb(uv_mbed_t* mbed, int status, void *p);
static void _mbed_alloc_done_cb(uv_mbed_t *mbed, size_t suggested_size, uv_buf_t *buf, void *p);
static void _mbed_data_received_cb(uv_mbed_t *mbed, ssize_t nread, uv_buf_t* buf, void *p);
static void _mbed_write_done_cb(uv_mbed_t *mbed, int status, void *p);
static void _mbed_close_done_cb(uv_mbed_t *mbed, void *p);

void tls_client_launch(struct tunnel_ctx *tunnel, struct server_config *config) {
    uv_loop_t *loop = tunnel->listener->loop;
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)calloc(1, sizeof(*ctx));
    ctx->mbed = uv_mbed_init(loop, config->over_tls_server_domain, NULL, 0);
    ctx->config = config;
    ctx->tunnel = tunnel;

    tunnel->tls_ctx = ctx;
    tunnel->tunnel_tls_send_data = &tunnel_tls_send_data;
    tunnel_add_dying_cb(tunnel, &tunnel_dying, ctx);

    uv_mbed_connect(ctx->mbed, config->remote_host, config->remote_port, _mbed_connect_done_cb, ctx);
}

void tls_client_shutdown(struct tunnel_ctx *tunnel) {
    struct tls_cli_ctx *ctx = tunnel->tls_ctx;
    uv_mbed_close(ctx->mbed, _mbed_close_done_cb, ctx);
}

static void _mbed_connect_done_cb(uv_mbed_t* mbed, int status, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    struct tunnel_ctx *tunnel = ctx->tunnel;

    assert(tunnel);

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
    *buf = uv_buf_init(base, (unsigned int)suggested_size);
}

static void _mbed_data_received_cb(uv_mbed_t *mbed, ssize_t nread, uv_buf_t* buf, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    struct tunnel_ctx *tunnel = ctx->tunnel;
    assert(ctx->mbed == mbed);
    if (nread > 0) {
        if (tunnel) {
        assert(tunnel->tunnel_tls_on_data_received);
        if (tunnel->tunnel_tls_on_data_received) {
            tunnel->tunnel_tls_on_data_received(tunnel, (uint8_t *)buf->base, (size_t)nread);
        }
        } else {
           uv_mbed_close(mbed, _mbed_close_done_cb, p);
        }
    } else if (nread < 0) {
        if (nread == UV_EOF) {
            pr_info("connection closed\n");
        } else {
            pr_err("read error %ld: %s\n", nread, uv_strerror((int) nread));
        }
        uv_mbed_close(mbed, _mbed_close_done_cb, p);
    }

    free(buf->base);
}

static void _mbed_write_done_cb(uv_mbed_t *mbed, int status, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    assert(ctx->mbed == mbed);
    if (status < 0) {
        pr_err("write failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close(mbed, _mbed_close_done_cb, p);
    }
}

static void _mbed_close_done_cb(uv_mbed_t *mbed, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    struct tunnel_ctx *tunnel = ctx->tunnel;
    assert(mbed == ctx->mbed);

    if (tunnel) {
        if (tunnel->tunnel_tls_on_shutting_down) {
            tunnel->tunnel_tls_on_shutting_down(tunnel);
        }
        tunnel->tls_ctx = NULL;
    }

    uv_mbed_free(mbed);
    free(ctx);
}

static void tunnel_tls_send_data(struct tunnel_ctx *tunnel, const uint8_t *data, size_t size) {
    struct tls_cli_ctx *ctx = tunnel->tls_ctx;
    uv_buf_t o = uv_buf_init((char *)data, (unsigned int)size);
    uv_mbed_write(ctx->mbed, &o, &_mbed_write_done_cb, ctx);
}

static void tunnel_dying(struct tunnel_ctx *tunnel, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    if (tunnel->tls_ctx == NULL) {
        return;
    }
    assert(tunnel == ctx->tunnel);
    ctx->tunnel = NULL;
}
