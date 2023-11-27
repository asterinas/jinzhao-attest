#ifndef UAL_INCLUDE_ATTESTATION_COMMON_TYPE_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_TYPE_H_

#include <string>
#include "attestation/common/error.h"
#include "attestation/common/log.h"

// include the protobuf message types here
#include "./attestation.pb.h"
#include "./crypto.pb.h"
#include "./pccs.pb.h"
#include "./tee.pb.h"
#include "./uas.pb.h"

#define RCAST(t, v) reinterpret_cast<t>((v))
#define SCAST(t, v) static_cast<t>((v))
#define CCAST(t, v) const_cast<t>((v))
#define RCCAST(t, v) reinterpret_cast<t>(const_cast<char*>((v)))
#define RCCHAR(v) reinterpret_cast<char*>((v))

// To ignore the parameters which is not used
#define TEE_UNREFERENCED_PARAMETER(p) \
  do {                                \
    static_cast<void>((p));           \
  } while (0)

// The template of one line code to check the function return value in
// TeeErrorCode type. Usage: TEE_CHECK_RETURN(functionName(arg-list));
#define TEE_CHECK_RETURN(r)   \
  do {                        \
    TeeErrorCode ret = (r);   \
    if (ret != TEE_SUCCESS) { \
      ELOG_ERROR_TRACE();     \
      return ret;             \
    }                         \
  } while (0)

#define TEE_CATCH_RETURN(r)                     \
  do {                                          \
    try {                                       \
      TeeErrorCode ret = (r);                   \
      if (ret != TEE_SUCCESS) {                 \
        ELOG_ERROR_TRACE();                     \
        return ret;                             \
      }                                         \
    } catch (std::exception & e) {              \
      TEE_LOG_ERROR("Exception: %s", e.what()); \
      return TEE_ERROR_CATCH_EXCEPTION;         \
    }                                           \
  } while (0)

// To check the pointer parameter
#define TEE_CHECK_NULLPTR(p)            \
  do {                                  \
    if ((p) == nullptr || ((p) == 0)) { \
      ELOG_ERROR("NULL pointer");       \
      return TEE_ERROR_PARAMETERS;      \
    }                                   \
  } while (0)

// To check the buf pointer and len parameter
#define TEE_CHECK_VALIDBUF(p, l)                      \
  do {                                                \
    if ((p) == nullptr || ((p) == 0) || ((l) == 0)) { \
      ELOG_ERROR("Buf null pointer or zero length");  \
      return TEE_ERROR_PARAMETERS;                    \
    }                                                 \
  } while (0)

// To check the string parameter is not empty
#define TEE_CHECK_EMPTY(s)         \
  do {                             \
    if (s.empty()) {               \
      ELOG_ERROR("Empty %s", #s);  \
      return TEE_ERROR_PARAMETERS; \
    }                              \
  } while (0)

// For safe string construct function
#define SAFESTR(s) (s) ? (s) : ""

// For API management
#define TEE_FUNCTION_DEPRECATED() \
  tee_printf("[WARN][%s:%d] %s() is deprecated!\n", __FILE__, __LINE__, __FUNCTION__)

// Define the user type of unified tee identity
typedef std::string UaTeeIdentity;
typedef char* UnifiedAttestationTeeIdentity;

// Generic format of trusted/untrusted function with serialized
// protobuffer message type in/out parameters
typedef TeeErrorCode (*UnifiedFunction)(const std::string& req_str,
                                        std::string* res_str);

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_TYPE_H_
