#include <cstdio>

#include <string>

#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/type.h"

#include "utils/untrusted/untrusted_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG
static size_t m_count = 0;
#endif

TeeErrorCode UntrustedMemoryAlloc(size_t size, char** buf) {
  if (size == 0) {
    return TEE_ERROR_PARAMETERS;
  }

  char* buf_allocated = static_cast<char*>(malloc(size));
  if (!buf_allocated) {
    TEE_LOG_ERROR("Fail to allocate memory: len=%ld", size);
    return TEE_ERROR_MALLOC;
  }

#ifdef DEBUG
  TEE_LOG_DEBUG("Untrusted Alloc[%ld]: +%p", ++m_count, buf_allocated);
#endif
  *buf = buf_allocated;
  return TEE_SUCCESS;
}

TeeErrorCode UntrustedMemoryFree(char** buf) {
  if (*buf == nullptr) {
    TEE_LOG_ERROR("UntrustedMemoryFree nullptr");
    return TEE_ERROR_PARAMETERS;
  }

#ifdef DEBUG
  TEE_LOG_DEBUG("Untrusted Free[%ld]: -%p", --m_count, *buf);
#endif
  free(*buf);
  *buf = 0;
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
