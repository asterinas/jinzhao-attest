#include <memory>
#include <string>

#include "attestation/common/log.h"
#include "attestation/common/type.h"

#include "attestation/instance/untrusted_unified_function.h"

namespace kubetee {
namespace attestation {

TeeErrorCode ReeUnifiedFunctions::RegisterFunctions() {
  if (is_functions_registed_) {
    return TEE_SUCCESS;
  }

  // Add internal untrusted unified funcitons
  TEE_LOG_INFO("Register internal untrusted unified functions ...");
  TEE_CHECK_RETURN(RegisterUntrustedUnifiedFunctionsInternal());

  // Add extended untrusted unified functions
  TEE_LOG_INFO("Register external untrusted unified functions ...");
  TEE_CHECK_RETURN(RegisterUntrustedUnifiedFunctionsEx());

  is_functions_registed_ = true;
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee

#ifdef __cplusplus
extern "C" {
#endif

// Register all above untrusted unified functions here
TeeErrorCode RegisterUntrustedUnifiedFunctionsInternal() {
  return TEE_SUCCESS;
}

// This week function may be overwritten in trusted application code.
TeeErrorCode __attribute__((weak)) RegisterUntrustedUnifiedFunctionsEx() {
  TEE_LOG_INFO("[WEAK] Register application untrusted functions ...");
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
