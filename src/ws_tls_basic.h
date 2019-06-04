#ifndef __WS_TLS_BASIC_H__
#define __WS_TLS_BASIC_H__

#define MAX_REQUEST_SIZE      0x8000

#define WEBSOCKET_STATUS_LINE "HTTP/1.1 101 Switching Protocols\r\n"

#define WEBSOCKET_RESPONSE                                                      \
    "HTTP/1.1 101 Switching Protocols\r\n"                                      \
    "Upgrade: websocket\r\n"                                                    \
    "Connection: Upgrade\r\n"                                                   \
    "Sec-WebSocket-Accept: Oy4NRAQ13jhfONC7bP8dTKb4PTU=\r\n"                    \
    "\r\n"

// Sec-WebSocket-Accept = 
//    toBase64( sha1( Sec-WebSocket-Key + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11 ) )

#define WEBSOCKET_REQUEST_FORMAT                                                \
    "GET %s HTTP/1.1\r\n"                                                       \
    "Host: %s:%d\r\n"                                                           \
    "Connection: Upgrade\r\n"                                                   \
    "Upgrade: websocket\r\n"                                                    \
    "Sec-WebSocket-Version: 13\r\n"                                             \
    "Sec-WebSocket-Key: w4v7O6xFTi36lq3RNcgctw==\r\n"                           \
    "Content-Type: application/octet-stream\r\n"                                \
    "Content-Length: %d\r\n"                                                    \
    "\r\n"

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const uint8_t * extract_http_data(const uint8_t *http_pkg, size_t size, size_t *data_size);

char * websocket_generate_sec_websocket_accept(const char *sec_websocket_key, void*(*allocator)(size_t));
unsigned char * websocket_server_retrieve_payload(unsigned char *buf, size_t len, void*(*allocator)(size_t), size_t *payload_len);
unsigned char * websocket_server_build_frame(const char *payload, size_t payload_len, void*(*allocator)(size_t), size_t *frame_len);
unsigned char * websocket_client_retrieve_payload(unsigned char *buf, size_t len, void*(*allocator)(size_t), size_t *payload_len);

#endif /* __WS_TLS_BASIC_H__ */
