/* OpenVNC C ABI v0. Mantido em sincronia com src/lib.rs. */
#ifndef OPENVNC_H
#define OPENVNC_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define OPENVNC_OK 0
#define OPENVNC_AGAIN 1
#define OPENVNC_EINVAL (-1)
#define OPENVNC_EPROTO (-2)
#define OPENVNC_EPANIC (-3)

typedef struct OpenvncDecoder OpenvncDecoder;
typedef struct OpenvncBuffer {
    uint8_t *data;
    size_t len;
} OpenvncBuffer;

uint16_t openvnc_protocol_version(void);
OpenvncDecoder *openvnc_decoder_new(uint32_t max_payload);
void openvnc_decoder_free(OpenvncDecoder *d);
int32_t openvnc_decoder_feed(OpenvncDecoder *d, const uint8_t *data, size_t len);
int32_t openvnc_decoder_next(OpenvncDecoder *d, uint16_t *msg_type);
int32_t openvnc_msg_pointer(const OpenvncDecoder *d, uint16_t *x, uint16_t *y, uint8_t *buttons);
int32_t openvnc_msg_key(const OpenvncDecoder *d, uint32_t *keysym, uint8_t *down);
int32_t openvnc_msg_clipboard(const OpenvncDecoder *d, OpenvncBuffer *out);
int32_t openvnc_encode_pointer(uint16_t x, uint16_t y, uint8_t buttons, OpenvncBuffer *out);
int32_t openvnc_encode_key(uint32_t keysym, uint8_t down, OpenvncBuffer *out);
int32_t openvnc_encode_clipboard(const uint8_t *text, size_t len, OpenvncBuffer *out);
void openvnc_buffer_free(OpenvncBuffer *b);

#ifdef __cplusplus
}
#endif
#endif
