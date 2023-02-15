#ifndef UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_MEMORY_H_
#define UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_MEMORY_H_

#include "attestation/common/error.h"
#include "attestation/common/type.h"

#ifdef __cplusplus
extern "C" {
#endif

extern TeeErrorCode UntrustedMemoryAlloc(size_t size, char** buf);
extern TeeErrorCode UntrustedMemoryFree(char** buf);

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_MEMORY_H_
