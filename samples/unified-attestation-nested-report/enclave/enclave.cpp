#include <string>

#include "unified_attestation/ua_trusted.h"

#include "enclave/enclave.h"

TeeErrorCode SampleEnclaveInit(const std::string& req_str,
                               std::string* res_str) {
  kubetee::UnifiedFunctionGenericRequest req;
  // Resposne is optional if there is nothing to be returned
  // kubetee::UnifiedFunctionGenericResponse res;
  JSON2PB(req_str, &req);

  // Here, add some test value for report data test
  // Warning: user_data from untrusted is no so secure.
  // In this sample, it's just convenient for generating different reports
  const std::string& hex_user_data = req.argv(0);
  TEE_CHECK_RETURN(TeeInstanceUpdateReportData(hex_user_data));

  // Resposne is optional if there is nothing to be returned
  // PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode RegisterTrustedUnifiedFunctionsEx() {
  ADD_TRUSTED_UNIFIED_FUNCTION(SampleEnclaveInit);
  return TEE_SUCCESS;
}
