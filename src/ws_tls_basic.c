#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
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

/*
https://segmentfault.com/a/1190000012709475

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
    // 0 OpCode(4b) = 1 (binary frame)
    frame_buf[0] = 0x82;

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

unsigned char * websocket_client_build_frame(const char *payload, size_t payload_len, void*(*allocator)(size_t), size_t *frame_len) {
    unsigned char mask[4];
    unsigned char finNopcode;
    size_t payload_len_small;
    unsigned int payload_offset = 6;
    size_t len_size;
    size_t i;
    size_t frame_size;
    unsigned char *data;

    if (payload==NULL || payload_len==0 || allocator==NULL) {
        return NULL;
    }

    // https://github.com/OlehKulykov/librws/blob/master/src/rws_frame.c
    // https://github.com/payden/libwsclient/blob/master/wsclient.c#L991

    finNopcode = 0x82; // FIN and binary opcode.
    if(payload_len <= 125) {
        frame_size = 6 + payload_len;
        payload_len_small = payload_len;
    } else if(payload_len > 125 && payload_len <= 0xffff) {
        frame_size = 8 + payload_len;
        payload_len_small = 126;
        payload_offset += 2;
    } else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
        frame_size = 14 + payload_len;
        payload_len_small = 127;
        payload_offset += 8;
    } else {
        assert(0);
        return NULL;
    }
    data = (unsigned char *) allocator(frame_size + 1);
    memset(data, 0, frame_size + 1);
    *data = finNopcode;
    *(data+1) = ((uint8_t)payload_len_small) | 0x80; // payload length with mask bit on
    if(payload_len_small == 126) {
        payload_len &= 0xffff;
        len_size = 2;
        for(i = 0; i < len_size; i++) {
            *(data+2+i) = *((unsigned char *)&payload_len+(len_size-i-1));
        }
    }
    if(payload_len_small == 127) {
        payload_len &= 0xffffffffffffffffLL;
        len_size = 8;
        for(i = 0; i < len_size; i++) {
            *(data+2+i) = *((unsigned char *)&payload_len+(len_size-i-1));
        }
    }

    random_bytes_generator("RANDOM_GEN", mask, sizeof(mask));
    for(i=0; i<4; i++) {
        *(data+(payload_offset-4)+i) = mask[i];
    }
    memcpy(data+payload_offset, payload, payload_len);
    for(i=0; i<payload_len; i++) {
        *(data+payload_offset+i) ^= mask[i % 4] & 0xff;
    }

    if (frame_len) {
        *frame_len  = frame_size;
    }
    return data;
}

uint8_t * websocket_retrieve_payload(const uint8_t *data, size_t dataLen, void*(*allocator)(size_t), size_t *packageLen)
{
    unsigned char *package = NULL;
    bool flagFIN = false, flagMask = false;
    unsigned char maskKey[4] = {0};
    char Opcode;
    size_t count = 0;
    size_t len = 0;
    size_t packageHeadLen = 0;

    if (allocator == NULL) { return NULL; }

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
        len = (size_t) ntohs( *((uint16_t *)(data + 2)) );
        packageHeadLen = 4 + count;
        if (flagMask) {
            memcpy(maskKey, data + 4, 4);
        }
    }
    else if (len == 127) {
        if (dataLen < 10) { return NULL; }
        // 使用 8 个字节存储长度时, 前 4 位必须为 0, 装不下那么多数据 .
        if(data[2] != 0 || data[3] != 0 || data[4] != 0 || data[5] != 0) {
            return NULL;
        }
        len = (size_t) ntohl( *((uint32_t *)(data + 6)) );
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

    if (dataLen < len + packageHeadLen) { return NULL; }
    if (packageLen) { *packageLen = len; }

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

