#include <string>

#include "unified_attestation/ua_trusted.h"

#include "enclave/enclave.h"

TeeErrorCode TrustedVerification(const std::string& req_str,
                                 std::string* res_str) {
  ELOG_INFO("Verify report in TEE ...");
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;
  kubetee::UnifiedAttestationAuthReport auth;
  JSON2PB(req_str, &req);
  JSON2PB(req.argv(0), &auth);  // The first argv saved auth_json

  kubetee::UnifiedAttestationPolicy policy;
  policy.set_pem_public_key(auth.pem_public_key());
  kubetee::UnifiedAttestationAttributes* attr = policy.add_main_attributes();
  attr->set_hex_ta_measurement("");
  attr->set_hex_signer("");
  attr->set_hex_prod_id("");
  attr->set_str_min_isvsvn("");
  attr->set_bool_debug_disabled("");
  attr->set_str_tee_platform("");
  // Must use the same value as what in generation sample code
  attr->set_hex_user_data("31323334");
  attr->set_hex_spid("");
  TEE_CHECK_RETURN(UaVerifyReport(auth.report(), policy));

  res.add_result()->assign("Verify successfully");
  PB2JSON(res, res_str);
  ELOG_INFO("Verify report in TEE successfully!");
  return TEE_SUCCESS;
}

TeeErrorCode RegisterTrustedUnifiedFunctionsEx() {
  ADD_TRUSTED_UNIFIED_FUNCTION(TrustedVerification);
  return TEE_SUCCESS;
}
