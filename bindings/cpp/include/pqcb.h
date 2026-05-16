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

uint32_t pqcb_abi_version(void);
PqcbVersion pqcb_version(void);

#ifdef __cplusplus
}
#endif

#endif
