#ifndef PQCB_H
#define PQCB_H

#include <stddef.h>
#include <stdbool.h>
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

typedef enum PqcbAlgorithm {
  PQCB_ALGORITHM_ML_KEM_768 = 1,
  PQCB_ALGORITHM_ML_DSA_65 = 2
} PqcbAlgorithm;

uint32_t pqcb_abi_version(void);
uint16_t pqcb_abi_version_major(void);
uint16_t pqcb_abi_version_minor(void);
PqcbVersion pqcb_version(void);
const char *pqcb_status_message(PqcbStatus status);
PqcbStatus pqcb_backend_available(uint32_t algorithm_id, bool *available);
void pqcb_buffer_free(PqcbOwnedBuffer buffer);
void pqcb_buffer_free_parts(uint8_t *data, size_t len);
PqcbStatus pqcb_ml_kem_768_keypair(PqcbOwnedBuffer *public_key_out,
                                   PqcbOwnedBuffer *secret_key_out);
PqcbStatus pqcb_ml_kem_768_encapsulate(PqcbBuffer public_key,
                                       PqcbOwnedBuffer *ciphertext_out,
                                       PqcbOwnedBuffer *shared_secret_out);
PqcbStatus pqcb_ml_kem_768_decapsulate(PqcbBuffer secret_key,
                                       PqcbBuffer ciphertext,
                                       PqcbOwnedBuffer *shared_secret_out);
PqcbStatus pqcb_ml_dsa_65_keypair(PqcbOwnedBuffer *public_key_out,
                                  PqcbOwnedBuffer *secret_key_out);
PqcbStatus pqcb_ml_dsa_65_sign(PqcbBuffer secret_key, PqcbBuffer message,
                               PqcbOwnedBuffer *signature_out);
PqcbStatus pqcb_ml_dsa_65_verify(PqcbBuffer public_key, PqcbBuffer message,
                                 PqcbBuffer signature);

#ifdef __cplusplus
}
#endif

#endif
