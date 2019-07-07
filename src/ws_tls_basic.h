#ifndef __WS_TLS_BASIC_H__
#define __WS_TLS_BASIC_H__

#define MAX_REQUEST_SIZE      0x8000

#define WEBSOCKET_STATUS    "Switching Protocols"
#define SEC_WEBSOKET_KEY    "Sec-WebSocket-Key"
#define SEC_WEBSOKET_ACCEPT "Sec-WebSocket-Accept"

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

/* see https://tools.ietf.org/html/rfc6455#section-7.4.1 */
typedef enum ws_close_reason {
    WS_CLOSE_REASON_UNKNOWN = 0,
    WS_CLOSE_REASON_NORMAL = 1000,
    WS_CLOSE_REASON_GOING_AWAY = 1001,
    WS_CLOSE_REASON_PROTOCOL_ERROR = 1002,
    WS_CLOSE_REASON_UNEXPECTED_DATA = 1003,
    WS_CLOSE_REASON_NO_REASON = 1005,
    WS_CLOSE_REASON_ABRUPTLY = 1006,
    WS_CLOSE_REASON_INCONSISTENT_DATA = 1007,
    WS_CLOSE_REASON_POLICY_VIOLATION = 1008,
    WS_CLOSE_REASON_TOO_BIG = 1009,
    WS_CLOSE_REASON_MISSING_EXTENSION = 1010,
    WS_CLOSE_REASON_SERVER_ERROR = 1011,
    WS_CLOSE_REASON_IANA_REGISTRY_START = 3000,
    WS_CLOSE_REASON_IANA_REGISTRY_END = 3999,
    WS_CLOSE_REASON_PRIVATE_START = 4000,
    WS_CLOSE_REASON_PRIVATE_END = 4999,
} ws_close_reason;

typedef enum ws_opcode {
    WS_OPCODE_CONTINUATION  = 0x0,
    WS_OPCODE_TEXT          = 0x1,
    WS_OPCODE_BINARY        = 0x2,
    WS_OPCODE_CLOSE         = 0x8,
    WS_OPCODE_PING          = 0x9,
    WS_OPCODE_PONG          = 0xa,
} ws_opcode;

typedef struct ws_frame_info {
    ws_opcode opcode;
    int fin;
    int masking;
    ws_close_reason reason;
} ws_frame_info;


void random_bytes_generator(const char *seed, uint8_t *buffer, size_t len);

char * websocket_generate_sec_websocket_key(void*(*allocator)(size_t));
char * websocket_generate_sec_websocket_accept(const char *sec_websocket_key, void*(*allocator)(size_t));
uint8_t * websocket_connect_request(const char *domain, uint16_t port, const char *url,
    const char *key, const uint8_t *data, size_t data_len, void*(*allocator)(size_t),
    size_t *result_len);
char * websocket_connect_response(const char *sec_websocket_key, void*(*allocator)(size_t));
uint8_t * websocket_build_frame(const ws_frame_info *info, const uint8_t *payload, size_t payload_len, void*(*allocator)(size_t), size_t *frame_len);
uint8_t * websocket_retrieve_payload(const uint8_t *data, size_t dataLen, void*(*allocator)(size_t), size_t *packageLen, ws_frame_info *info);


uint16_t ws_ntoh16(uint16_t n);
uint16_t ws_hton16(uint16_t n);

uint32_t ws_ntoh32(uint32_t n);
uint32_t ws_hton32(uint32_t n);

uint64_t ws_ntoh64(uint64_t n);
uint64_t ws_hton64(uint64_t n);


#endif /* __WS_TLS_BASIC_H__ */
