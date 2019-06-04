#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/sha1.h>
#include <mbedtls/base64.h>

#if defined(WIN32) || defined(_WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "ws_tls_basic.h"

const uint8_t * extract_http_data(const uint8_t *http_pkg, size_t size, size_t *data_size) {
    char *ptmp = (char *)http_pkg;
    size_t len0 = (size_t)size;
    size_t read_len = (size_t)size;
    char *px = NULL;

#define GET_REQUEST_END "\r\n\r\n"
    px = strstr((char *)http_pkg, GET_REQUEST_END);
    if (px != NULL) {
        ptmp = px + strlen(GET_REQUEST_END);
        len0 = len0 - (size_t)(ptmp - (char *)http_pkg);
    }

#define CONTENT_LENGTH "Content-Length:"
    px = strstr((char *)http_pkg, CONTENT_LENGTH);
    if (px) {
        px = px + strlen(CONTENT_LENGTH);
        read_len = (size_t) strtol(px, NULL, 10);
    }
    if (read_len == len0) {
        if (data_size) {
            *data_size = len0;
        }
    } else {
        ptmp = (char *)http_pkg;
    }
    return (uint8_t *)ptmp;
}

char * websocket_generate_sec_websocket_accept(const char *sec_websocket_key, void*(*allocator)(size_t)) {
    mbedtls_sha1_context sha1_ctx = { 0 };
    unsigned char sha1_hash[SHA_DIGEST_LENGTH] = { 0 };
    size_t b64_str_len = 0;
    char *b64_str;
    size_t concatenated_val_len;
    char *concatenated_val;

    if (sec_websocket_key==NULL || 0==strlen(sec_websocket_key) || allocator==NULL) {
        return NULL;
    }

    concatenated_val_len = strlen(sec_websocket_key) + strlen(WEBSOCKET_GUID);
    concatenated_val = (char *) calloc(concatenated_val_len + 1, sizeof(char));
    strcat(concatenated_val, sec_websocket_key);
    strcat(concatenated_val, WEBSOCKET_GUID);

    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    mbedtls_sha1_update(&sha1_ctx, (unsigned char *)concatenated_val, concatenated_val_len);
    mbedtls_sha1_finish(&sha1_ctx, sha1_hash);
    mbedtls_sha1_free(&sha1_ctx);

    mbedtls_base64_encode(NULL, 0, &b64_str_len, sha1_hash, sizeof(sha1_hash));

    b64_str = (char *) allocator(b64_str_len + 1);
    b64_str[b64_str_len] = 0;

    mbedtls_base64_encode((unsigned char *)b64_str, b64_str_len, &b64_str_len, sha1_hash, sizeof(sha1_hash));

    free(concatenated_val);

    return b64_str;
}

unsigned char * websocket_server_retrieve_payload(unsigned char *buf, size_t len, void*(*allocator)(size_t), size_t *payload_len) {
    if (buf==NULL || len==0 || allocator==NULL) {
        return NULL;
    }
    else {
        // A client message follows the binary format outlined in the RFC
        unsigned char has_fin = buf[0] & 0x80;
        unsigned char has_rsv1 = buf[0] & 0x40;
        unsigned char has_rsv2 = buf[0] & 0x20;
        unsigned char has_rsv3 = buf[0] & 0x10;
        unsigned char op_code = buf[0] & 0xF;
        unsigned char has_mask = buf[1] & 0x80;

        unsigned char small_payload_len = buf[1] & 0x7F;

        unsigned char mask_offset;
        size_t _payload_len;

        unsigned char masking_key[4];
        unsigned char *masked_payload_data;
        const char *payload_start;
        size_t i;

        if (small_payload_len < 126) {
            // Just use the specified length
            _payload_len = (size_t) small_payload_len;
            mask_offset = 2;
        } else if (small_payload_len == 126) {
            unsigned short payload_len_nbo = *((unsigned short *)(buf + 2));
            _payload_len = (size_t) ntohs(payload_len_nbo);
            mask_offset = 4;
        } else {
            // The following 8 bytes are an unsigned 64-bit integer. MSB = 0
            // multi-byte lengths are in network byte order
            fprintf(stderr, "64-bit payload lengths not supported (no ntohll available)\n");
            exit(1);
            mask_offset = 10;
        }

        masking_key[0] = buf[mask_offset];
        masking_key[1] = buf[mask_offset + 1];
        masking_key[2] = buf[mask_offset + 2];
        masking_key[3] = buf[mask_offset + 3];

        masked_payload_data = (unsigned char *) allocator(_payload_len + 1);
        if (masked_payload_data == NULL) {
            return NULL;
        }
        masked_payload_data[_payload_len] = 0;

        payload_start = (char *)buf + mask_offset + 4;
        memcpy(masked_payload_data, payload_start, _payload_len);

        for (i = 0; i < _payload_len; i++) {
            char mask = masking_key[i % 4];
            masked_payload_data[i] = masked_payload_data[i] ^ mask;
        }

        if (payload_len) {
            *payload_len = _payload_len;
        }

        return masked_payload_data;
    }
}

unsigned char * websocket_server_build_frame(const char *payload, size_t payload_len, void*(*allocator)(size_t), size_t *frame_len) {
    // RFC6455 for websocket: https://tools.ietf.org/html/rfc6455
    unsigned char *frame_buf;
    size_t offset;
    size_t msg_size;

    if (payload==NULL || payload_len==0 || allocator==NULL) {
        return NULL;
    }

    frame_buf = (unsigned char *) allocator(payload_len + 10 + 1);
    if (frame_buf == NULL) {
        return NULL;
    }
    memset(frame_buf, 0, payload_len + 10 + 1);

    // FIN = 1 (it's the last message) RSV1 = 0, RSV2 = 0, RSV3 =
    // 0 OpCode(4b) = 1 (text)
    frame_buf[0] = 0x81;

    if (payload_len < 126) {
        offset = 2;
        frame_buf[1] = (char)payload_len;
    } else if (payload_len < 65536) {
        offset = 4;
        frame_buf[1] = 126;
        *((unsigned short *)(frame_buf + 2)) = htons((unsigned short)payload_len);
    } else {
        fprintf(stderr, "Cannot write payloads larger than 2^32 bytes (can't htoni)");
        exit(1);
    }

    memcpy(frame_buf + offset, payload, payload_len);

    msg_size = offset + payload_len;

    if (frame_len) {
        *frame_len = msg_size;
    }

    return frame_buf;
}

unsigned char * websocket_client_retrieve_payload(unsigned char *buf, size_t len, void*(*allocator)(size_t), size_t *payload_len) {
    return NULL;
}
