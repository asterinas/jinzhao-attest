#ifndef UAL_INCLUDE_ATTESTATION_COMMON_LOG_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_LOG_H_

#include <string>

extern "C" int tee_printf(const char* fmt, ...);

// Uncomment the line to enable buffer print
// #define DEBUG_BUFFER

#ifdef NOLOG
#define TEE_LOG_TRACE(fmt, ...)
#define TEE_LOG_DEBUG(fmt, ...)
#define TEE_LOG_INFO(fmt, ...)
#define TEE_LOG_WARN(fmt, ...)
#define TEE_LOG_ERROR(fmt, ...)
#define TEE_LOG_ERROR_TRACE()
#define TEE_LOG_BUFFER(name, ptr, len)
#define ELOG_TRACE(fmt, ...)
#define ELOG_DEBUG(fmt, ...)
#define ELOG_INFO(fmt, ...)
#define ELOG_WARN(fmt, ...)
#define ELOG_ERROR(fmt, ...)
#define ELOG_ERROR_TRACE()
#define ELOG_BUFFER(name, ptr, len)
#define HEX_PRINTF(name, ptr, len)

#else  // NOLOG

#ifdef TRACELOG
#define TEE_LOG_TRACE(fmt, ...) \
  tee_printf("[TRACE][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define TEE_LOG_TRACE(fmt, ...)
#endif

#ifdef DEBUGLOG
#define HEX_PRINTF(name, ptr, size)                                            \
  do {                                                                         \
    const uint8_t* buf = reinterpret_cast<const uint8_t*>(ptr);                \
    int len = static_cast<int>((size));                                        \
    tee_printf("Buffer %s, %p, len: %d(0x%x)\n", (name), (buf), (len), (len)); \
    for (int i = 0; i < len; i++) {                                            \
      if (i && (0 == i % 16)) tee_printf("\n");                                \
      tee_printf("%02x ", buf[i]);                                             \
    }                                                                          \
    tee_printf("\n");                                                          \
  } while (0)
#else
#define HEX_PRINTF(name, ptr, len)
#endif

// TEE_LOG_XXX are used in untrusted code, only disable
// TEE_LOG_DEBUG and TEE_LOG_BUFFER in release mode.
#ifdef DEBUGLOG
#define TEE_LOG_DEBUG(fmt, ...) \
  tee_printf("[DEBUG][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#ifdef DEBUG_BUFFER
#define TEE_LOG_BUFFER(name, ptr, size) HEX_PRINTF(name, ptr, size)
#else
#define TEE_LOG_BUFFER(name, ptr, len)
#endif

#else  // not DEBUG for TEE_LOG_XXX
#define TEE_LOG_DEBUG(fmt, ...)
#define TEE_LOG_BUFFER(name, ptr, len)
#endif  // end DEBUG for TEE_LOG_XXX

// Always enable INFO/WARN/ERROR for untrusted log message
#define TEE_LOG_INFO(fmt, ...) \
  tee_printf("[INFO][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define TEE_LOG_WARN(fmt, ...) \
  tee_printf("[WARN][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define TEE_LOG_ERROR(fmt, ...) \
  tee_printf("[ERROR][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define TEE_LOG_ERROR_TRACE() TEE_LOG_ERROR("[Function] %s", __FUNCTION__)

// ELOG_XXX are used in common code and also trusted code
// Only ELOG_ERROR is still enabled when enclave is release mode
#ifdef TRACELOG
#define ELOG_TRACE(fmt, ...) \
  tee_printf("[TRACE][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define ELOG_TRACE(fmt, ...)
#endif

#ifdef DEBUGLOG
#define ELOG_DEBUG(fmt, ...) \
  tee_printf("[DEBUG][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#ifdef DEBUG_BUFFER
#define ELOG_BUFFER(name, ptr, size) HEX_PRINTF(name, ptr, size)
#else
#define ELOG_BUFFER(name, ptr, len)
#endif

#else  // not DEBUG for ELOG_XXX

#define ELOG_DEBUG(fmt, ...)
#define ELOG_BUFFER(name, ptr, len)

#endif

// Always enalbe INFO/WARN/ERROR for trusted log message
#define ELOG_INFO(fmt, ...) \
  tee_printf("[INFO][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define ELOG_WARN(fmt, ...) \
  tee_printf("[WARN][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define ELOG_ERROR(fmt, ...) \
  tee_printf("[ERROR][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define ELOG_ERROR_TRACE() ELOG_ERROR("[Function] %s", __FUNCTION__)

#endif  // NOLOG

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_LOG_H_
