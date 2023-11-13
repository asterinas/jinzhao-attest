#include <string>

#include "./sgx_urts.h"

#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/type.h"

#include "attestation/verification/ua_verification.h"

#include "generation/platforms/sgx_common/untrusted/untrusted_sgx_common.h"
#include "generation/platforms/sgx_common/untrusted/untrusted_sgx_common_ecall.h"

#ifdef __cplusplus
extern "C" {
#endif

/// The C++ API for unified attestation submodule attesters verification
/// This is the untrused version which is called in main report generation
/// We place them here because they ared used when generate report, and we
/// want to keep the verification simple enough.
#ifdef UA_ENV_TYPE_SGXSDK
TeeErrorCode SgxVerifySubReports(
    const std::string& tee_identity,
    const kubetee::UnifiedAttestationAuthReports& auth_reports,
    const kubetee::UnifiedAttestationPolicy& policy,
    std::string* results_json) {
  if (tee_identity.empty()) {
    TEE_LOG_ERROR("Empty tee identity");
    return TEE_ERROR_ENCLAVE_NOTINITIALIZED;
  }

  std::string auth_reports_json;
  std::string policy_json;
  PB2JSON(auth_reports, &auth_reports_json);
  PB2JSON(policy, &policy_json);

  std::string nested_report_str(auth_reports.reports_size() * 512 + 4096, 0);
  TeeErrorCode ret = 0;
  int nested_report_len;
  sgx_enclave_id_t eid = 0;
  try {
    eid = std::stoll(tee_identity);
  } catch (std::exception& e) {
    return TEE_ERROR_INVALID_ENCLAVE_ID;
  }
  sgx_status_t rc = ecall_UaVerifySubReorts(
      eid, &ret, auth_reports_json.c_str(), policy_json.c_str(),
      CCAST(char*, nested_report_str.data()), nested_report_str.size(),
      &nested_report_len);
  if (ret || rc) {
    TEE_LOG_ERROR("Fail to verify sub reports: 0x%x/0x%x", ret, rc);
    return TEE_ERROR_RA_VERIFY_NESTED_REPORTS;
  }
  TEE_LOG_DEBUG("Nested report[%d]: %s", nested_report_len,
                nested_report_str.data());
  results_json->assign(nested_report_str.data(), nested_report_len);
  return TEE_SUCCESS;
}
#endif

#ifdef __cplusplus
}
#endif
