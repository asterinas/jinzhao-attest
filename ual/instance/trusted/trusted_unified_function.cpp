#include <memory>
#include <string>

#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
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

TeeErrorCode TeeSealData(const std::string& req_str, std::string* res_str) {
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;
  JSON2PB(req_str, &req);

  const std::string& plain_str = req.argv(0);
  const std::string& bound_str = req.argv(1);
  std::string sealed_str;
  bool bound = ((bound_str == "true") || (bound_str == "TRUE"));
  TEE_CHECK_RETURN(kubetee::attestation::TeeInstance::GetInstance().SealData(
      plain_str, &sealed_str, bound));
  kubetee::common::DataBytes sealed_hex(sealed_str);
  res.add_result()->assign(sealed_hex.ToHexStr().GetStr());
  TEE_LOG_DEBUG("TeeSealData, sealed_size=%d", res.result(0).size());
  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeUnsealData(const std::string& req_str, std::string* res_str) {
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;
  JSON2PB(req_str, &req);

  kubetee::common::DataBytes sealed_hex(req.argv(0));
  TEE_LOG_DEBUG("TeeUnsealData, sealed_size=%d", sealed_hex.size());
  std::string sealed_str = sealed_hex.FromHexStr().GetStr();
  std::string* plain_str = res.add_result();
  TEE_CHECK_RETURN(kubetee::attestation::TeeInstance::GetInstance().UnsealData(
      sealed_str, plain_str));
  TEE_LOG_DEBUG("TeeUnsealData, plain_size=%d", res.result(0).size());
  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

// Register all above trusted unified functions here
TeeErrorCode RegisterTrustedUnifiedFunctionsInternal() {
  TEE_LOG_INFO("Register TEE trusted functions ...");
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeSealData);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeUnsealData);
  return TEE_SUCCESS;
}

// This week function may be overwritten in trusted application code.
TeeErrorCode __attribute__((weak)) RegisterTrustedUnifiedFunctionsEx() {
  TEE_LOG_INFO("[WEAK] Register external TEE trusted functions ...");
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
