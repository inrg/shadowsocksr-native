#ifndef __WS_TLS_BASIC_H__
#define __WS_TLS_BASIC_H__

#define MAX_REQUEST_SIZE      0x8000

#define WEBSOCKET_STATUS    "Switching Protocols"
#define SEC_WEBSOKET_KEY    "Sec-WebSocket-Key"
#define SEC_WEBSOKET_ACCEPT "Sec-WebSocket-Accept"

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

void random_bytes_generator(const char *seed, uint8_t *buffer, size_t len);

char * websocket_generate_sec_websocket_key(void*(*allocator)(size_t));
char * websocket_generate_sec_websocket_accept(const char *sec_websocket_key, void*(*allocator)(size_t));
uint8_t * websocket_connect_request(const char *domain, uint16_t port, const char *url,
    const char *key, const uint8_t *data, size_t data_len, void*(*allocator)(size_t),
    size_t *result_len);
char * websocket_connect_response(const char *sec_websocket_key, void*(*allocator)(size_t));
uint8_t * websocket_build_frame(int masked, const uint8_t *payload, size_t payload_len, void*(*allocator)(size_t), size_t *frame_len);
uint8_t * websocket_retrieve_payload(const uint8_t *data, size_t dataLen, void*(*allocator)(size_t), size_t *packageLen);

#endif /* __WS_TLS_BASIC_H__ */
