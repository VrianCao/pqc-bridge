#ifndef PQCB_H
#define PQCB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PqcbVersion {
  uint16_t major;
  uint16_t minor;
  uint16_t patch;
} PqcbVersion;

typedef enum PqcbStatus {
  PQCB_STATUS_OK = 0,
  PQCB_STATUS_NULL_POINTER = 1,
  PQCB_STATUS_INVALID_LENGTH = 2,
  PQCB_STATUS_INVALID_ALGORITHM = 3,
  PQCB_STATUS_BACKEND_UNAVAILABLE = 4,
  PQCB_STATUS_VERIFICATION_FAILED = 5,
  PQCB_STATUS_CRYPTO_FAILURE = 6,
  PQCB_STATUS_PANIC = 255
} PqcbStatus;

typedef struct PqcbBuffer {
  const uint8_t *data;
  size_t len;
} PqcbBuffer;

typedef struct PqcbOwnedBuffer {
  uint8_t *data;
  size_t len;
} PqcbOwnedBuffer;

uint32_t pqcb_abi_version(void);
PqcbVersion pqcb_version(void);
const char *pqcb_status_message(PqcbStatus status);
void pqcb_buffer_free(PqcbOwnedBuffer buffer);

#ifdef __cplusplus
}
#endif

#endif
