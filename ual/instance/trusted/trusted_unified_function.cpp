#include <memory>
#include <string>

#include "attestation/common/log.h"
#include "attestation/common/type.h"
#include "attestation/instance/trusted_tee_instance.h"

#include "attestation/instance/trusted_unified_function.h"

namespace kubetee {
namespace attestation {

TeeErrorCode TeeUnifiedFunctions::RegisterFunctions() {
  if (is_functions_registed_) {
    return TEE_SUCCESS;
  }

  ELOG_DEBUG("Register trusted functions ...");
  TeeErrorCode ret = RegisterTrustedUnifiedFunctionsInternal();
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }
  ret = RegisterTrustedUnifiedFunctionsEx();
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }
  is_functions_registed_ = true;
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee

#ifdef __cplusplus
extern "C" {
#endif

// Register all above trusted unified functions here
TeeErrorCode RegisterTrustedUnifiedFunctionsInternal() {
  // ADD_TRUSTED_UNIFIED_FUNCTION(TeeInitializeEnclave);
  return TEE_SUCCESS;
}

// This week function may be overwritten in trusted application code.
TeeErrorCode __attribute__((weak)) RegisterTrustedUnifiedFunctionsEx() {
  TEE_LOG_INFO("[WEAK] Register TEE trusted functions ...");
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
