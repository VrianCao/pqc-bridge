#ifndef PQCB_H
#define PQCB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PqcbVersion {
  uint16_t major;
  uint16_t minor;
  uint16_t patch;
} PqcbVersion;

/*
 * v0.2 ABI plan:
 * - Caller-owned inputs use PqcbBuffer.
 * - Library-owned outputs use PqcbOwnedBuffer and must be released with
 *   pqcb_buffer_free.
 * - Primitive functions return PqcbStatus and never unwind across the C
 *   boundary.
 *
 * Concrete buffer/result structs and primitive function declarations are added
 * with the v0.2 implementation tasks that follow docs/ABI.md.
 */

uint32_t pqcb_abi_version(void);
PqcbVersion pqcb_version(void);

#ifdef __cplusplus
}
#endif

#endif
