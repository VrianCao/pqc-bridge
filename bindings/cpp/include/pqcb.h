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

typedef uint32_t PqcbStatus;
#define PQCB_STATUS_OK ((PqcbStatus)0u)
#define PQCB_STATUS_NULL_POINTER ((PqcbStatus)1u)
#define PQCB_STATUS_INVALID_LENGTH ((PqcbStatus)2u)
#define PQCB_STATUS_INVALID_ALGORITHM ((PqcbStatus)3u)
#define PQCB_STATUS_BACKEND_UNAVAILABLE ((PqcbStatus)4u)
#define PQCB_STATUS_VERIFICATION_FAILED ((PqcbStatus)5u)
#define PQCB_STATUS_CRYPTO_FAILURE ((PqcbStatus)6u)
#define PQCB_STATUS_PANIC ((PqcbStatus)255u)

typedef struct PqcbBuffer {
  const uint8_t *data;
  size_t len;
} PqcbBuffer;

typedef struct PqcbOwnedBuffer {
  uint8_t *data;
  size_t len;
} PqcbOwnedBuffer;

typedef uint32_t PqcbAlgorithm;
#define PQCB_ALGORITHM_ML_KEM_768 ((PqcbAlgorithm)1u)
#define PQCB_ALGORITHM_ML_DSA_65 ((PqcbAlgorithm)2u)

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
