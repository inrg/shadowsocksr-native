#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <mbedtls/sha1.h>
#include <mbedtls/base64.h>

#include "ws_tls_basic.h"

/*
https://segmentfault.com/a/1190000012709475

RFC6455 for websocket: https://tools.ietf.org/html/rfc6455

https://github.com/abbshr/abbshr.github.io/issues/22

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
*/

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

void random_bytes_generator(const char *seed, uint8_t *output, size_t len) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    if (seed==NULL || strlen(seed)==0 || output==NULL || len==0) {
        return;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)seed, strlen(seed));
    mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF);
    mbedtls_ctr_drbg_random(&ctr_drbg, output, len);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}

char * websocket_generate_sec_websocket_key(void*(*allocator)(size_t)) {
    static int count = 0;
    char seed[0x100] = { 0 };
    uint8_t data[20] = { 0 };
    size_t b64_str_len = 0;
    char *b64_str;

    if (allocator == NULL) {
        return NULL;
    }
    sprintf(seed, "seed %d seed %d", count, count+1);
    count++;
    random_bytes_generator(seed, data, sizeof(data));

    mbedtls_base64_encode(NULL, 0, &b64_str_len, data, sizeof(data));

    b64_str = (char *) allocator(b64_str_len + 1);
    b64_str[b64_str_len] = 0;

    mbedtls_base64_encode((unsigned char *)b64_str, b64_str_len, &b64_str_len, data, sizeof(data));

    return b64_str;
}

//
// Sec-WebSocket-Accept = 
//    toBase64( sha1( Sec-WebSocket-Key + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11 ) )
//
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

#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

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

#define WEBSOCKET_REQUEST_FORMAT                                                \
    "GET %s HTTP/1.1\r\n"                                                       \
    "Host: %s:%d\r\n"                                                           \
    "Connection: Upgrade\r\n"                                                   \
    "Upgrade: websocket\r\n"                                                    \
    "Sec-WebSocket-Version: 13\r\n"                                             \
    "Sec-WebSocket-Key: %s\r\n"                                                 \
    "Content-Type: application/octet-stream\r\n"                                \
    "Content-Length: %d\r\n"                                                    \
    "\r\n"

uint8_t * websocket_connect_request(const char *domain, uint16_t port, const char *url,
    const char *key, const uint8_t *data, size_t data_len, void*(*allocator)(size_t),
    size_t *result_len)
{
    uint8_t *buf = NULL;
    const char *fmt = WEBSOCKET_REQUEST_FORMAT;
    size_t buf_len = 0;
    if (domain==NULL || port==0 || key==NULL || allocator==NULL) {
        return NULL;
    }

    url = url?url:"/";

    buf_len = strlen(fmt) + strlen(domain) + 5 + strlen(url) + strlen(key) + data_len;

    buf = (uint8_t *) allocator(buf_len + 1);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf, 0, buf_len + 1);

    sprintf((char *)buf, fmt, url, domain, (int)port, key, (int)data_len);
    buf_len = strlen((char *)buf);

    if (data && data_len) {
        memcpy(buf + buf_len, data, data_len);
        buf_len += data_len;
    }

    if (result_len) {
        *result_len = buf_len;
    }

    return buf;
}

#define WEBSOCKET_RESPONSE                                                      \
    "HTTP/1.1 101 Switching Protocols\r\n"                                      \
    "Upgrade: websocket\r\n"                                                    \
    "Connection: Upgrade\r\n"                                                   \
    "Sec-WebSocket-Accept: %s\r\n"                                              \
    "\r\n"

char * websocket_connect_response(const char *sec_websocket_key, void*(*allocator)(size_t)) {
    char *calc_val;
    char *tls_ok;
    if (sec_websocket_key==NULL || allocator==NULL) {
        return NULL;
    }
    calc_val = websocket_generate_sec_websocket_accept(sec_websocket_key, &malloc);
    if (calc_val == NULL) {
        return NULL;
    }
    tls_ok = (char *) allocator(strlen(WEBSOCKET_RESPONSE) + strlen(calc_val));

    sprintf((char *)tls_ok, WEBSOCKET_RESPONSE, calc_val);
    free(calc_val);

    return tls_ok;
}

uint8_t * websocket_build_frame(ws_frame_info *info, const uint8_t *payload, size_t payload_len, void*(*allocator)(size_t)) {
    uint8_t finNopcode;
    size_t payload_len_small;
    size_t payload_offset;
    size_t len_size = 0;
    size_t frame_size;
    uint8_t *data;

    if (info==NULL || allocator==NULL) {
        return NULL;
    }

#define WS_MASK_SIZE 4

    // FIN = 1 (it's the last message) RSV1 = 0, RSV2 = 0, RSV3 = 0
    // OpCode(4b) = 2 (binary frame)
    finNopcode = (info->fin ? 0x80 : 0x00) | info->opcode; //; 0x82;
    if(payload_len <= 125) {
        payload_len_small = payload_len;
        len_size = 0;
    } else if(payload_len > 125 && payload_len <= 0xffff) {
        payload_len_small = 126;
        len_size = sizeof(uint16_t);
    } else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
        payload_len_small = 127;
        len_size = sizeof(uint64_t);
    } else {
        assert(0);
        return NULL;
    }

    payload_offset = 2 + len_size + (info->masking ? WS_MASK_SIZE : 0);
    frame_size = payload_offset + payload_len;

    data = (unsigned char *) allocator(frame_size + 1);
    memset(data, 0, frame_size + 1);
    *data = finNopcode;
    if (info->masking) {
        *(data + 1) = ((uint8_t)payload_len_small) | 0x80; // payload length with mask bit on
    } else {
        *(data + 1) = ((uint8_t)payload_len_small) & 0x7F;
    }
    if(payload_len_small == 126) {
        payload_len &= 0xffff;
        *((uint16_t *)(data + 2)) = (uint16_t)ws_hton16((uint16_t)payload_len);
    }
    if(payload_len_small == 127) {
        payload_len &= 0xffffffffffffffffLL;
        *((uint64_t *)(data + 2)) = (uint64_t)ws_hton64((uint64_t)payload_len);
    }

    memcpy(data + payload_offset, payload, payload_len);

    if (info->masking) {
        size_t i;
        uint8_t mask[WS_MASK_SIZE];
        random_bytes_generator("RANDOM_GEN", mask, sizeof(mask));
        memcpy(data + (payload_offset - sizeof(mask)), mask, sizeof(mask));

        for (i = 0; i < payload_len; i++) {
            *(data + payload_offset + i) ^= mask[i % sizeof(mask)] & 0xff;
        }
    }

    info->frame_size = frame_size;
    info->payload_size = payload_len;

    return data;
}

uint8_t * websocket_retrieve_payload(const uint8_t *data, size_t dataLen, void*(*allocator)(size_t), ws_frame_info *info)
{
    unsigned char *package = NULL;
    bool flagFIN = false, flagMask = false;
    unsigned char maskKey[4] = {0};
    char Opcode;
    size_t count = 0;
    size_t len = 0;
    size_t packageHeadLen = 0;

    if (allocator == NULL || info==NULL) {
        assert(0);
        return NULL;
    }

    if (dataLen < 2) { return NULL; }

    // https://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-13#section-5 

    Opcode = (data[0] & 0x0F);

    if ((data[0] & 0x80) == 0x80) {
        flagFIN = true;
    }

    if ((data[1] & 0x80) == 0x80) {
        flagMask = true;
        count = 4;
    }

    len = (size_t)(data[1] & 0x7F);
    if (len == 126) {
        if(dataLen < 4) { return NULL; }
        len = (size_t) ws_ntoh16( *((uint16_t *)(data + 2)) );
        packageHeadLen = 4 + count;
        if (flagMask) {
            memcpy(maskKey, data + 4, 4);
        }
    }
    else if (len == 127) {
        if (dataLen < 10) { return NULL; }
        // 使用 8 个字节存储长度时, 前 4 位必须为 0, 装不下那么多数据 .
        if(*((uint32_t *)(data + 2)) != 0) {
            assert(!"the data too big!!!");
            return NULL;
        }
        len = (size_t) ws_ntoh64( *((uint64_t *)(data + 2)) );
        packageHeadLen = 10 + count;

        if (flagMask) {
            memcpy(maskKey, data + 10, 4);
        }
    }
    else {
        packageHeadLen = 2 + count;
        if (flagMask) {
            memcpy(maskKey, data + 2, 4);
        }
    }

    info->opcode = (ws_opcode)Opcode;
    info->fin = flagFIN;
    info->masking = flagMask;
    info->frame_size = len + packageHeadLen;
    info->payload_size = len;

    if (dataLen < info->frame_size) { return NULL; }

    package = (uint8_t *) allocator( len + 1 );
    memset(package, 0, len + 1);

    if (flagMask) {
        // 解包数据使用掩码时, 使用异或解码, maskKey[4] 依次和数据异或运算 .
        size_t i;
        for (i = 0; i < len; i++) {
            uint8_t mask = maskKey[i % 4]; // maskKey[4] 循环使用 .
            package[i] = data[i + packageHeadLen] ^ mask;
        }
    } else {
        // 解包数据没使用掩码, 直接复制数据段...
        memcpy(package, data + packageHeadLen, len);
    }

    return package;
}

#include <stdint.h>
#undef WS_IS_LITTLE_ENDIAN
#define WS_IS_LITTLE_ENDIAN() (*(uint16_t*)"\0\1">>8)

#undef WS_IS_BIG_ENDIAN
#define WS_IS_BIG_ENDIAN() (*(uint16_t*)"\1\0">>8)

void _ws_hton(void *mem, size_t len) {
    if ( WS_IS_LITTLE_ENDIAN() ) {
        uint8_t *bytes;
        size_t i, mid;

        if (len % 2) { return; }

        mid = len / 2;
        bytes = (uint8_t *)mem;
        for (i = 0; i < mid; i++) {
            uint8_t tmp = bytes[i];
            bytes[i] = bytes[len - i - 1];
            bytes[len - i - 1] = tmp;
        }
    }
}

#if 0
void _ws_ntoh(void *mem, size_t len) {
    _ws_hton(mem, len);
}
#endif

uint16_t ws_ntoh16(uint16_t n) {
    _ws_hton(&n, sizeof(n)); // _ws_ntoh(&n, sizeof(n));
    return n;
}

uint16_t ws_hton16(uint16_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

uint32_t ws_ntoh32(uint32_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

uint32_t ws_hton32(uint32_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

uint64_t ws_ntoh64(uint64_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

uint64_t ws_hton64(uint64_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}
