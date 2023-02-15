#include <map>
#include <string>

#include "attestation/common/attestation.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"
#include "attestation/generation/core/generator.h"
#include "attestation/generation/ua_generation.h"
#include "attestation/generation/unified_attestation_generation.h"

#include "utils/untrusted/untrusted_ua_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/// The C API for unified attestation authentication report generation
int UnifiedAttestationGenerateReport(const char* tee_identity,
                                     const char* report_type,
                                     const char* report_hex_nonce,
                                     const char* report_params_buf,
                                     const unsigned int report_params_len,
                                     char* report_json_buf,
                                     unsigned int* report_json_len) {
  TEE_CHECK_VALIDBUF(report_json_buf, *report_json_len);
  UaReportGenerationParameters param;
  param.tee_identity = SAFESTR(tee_identity);
  param.report_type = SAFESTR(report_type);
  param.report_hex_nonce = SAFESTR(report_hex_nonce);
  if (report_params_buf && report_params_len) {
    std::string report_params(report_params_buf, report_params_len);
    JSON2PB(report_params, &param.others);
  }

  std::string ua_report_json;
  TEE_CATCH_RETURN(UaGenerateReportJson(&param, &ua_report_json));
  // Check the max length of the output buffer
  if (*report_json_len <= ua_report_json.size()) {
    TEE_LOG_ERROR("Too small auth report buf buf_size: %d, report_size: %ld\n",
                  *report_json_len, ua_report_json.size());
    return TEE_ERROR_RA_SMALLER_REPORT_BUFFER;
  }
  // Copy the JSON string into the output buffer
  *report_json_len = ua_report_json.size();
  memcpy(report_json_buf, ua_report_json.data(), *report_json_len);
  return TEE_SUCCESS;
}

int UnifiedAttestationGenerateAuthReport(const char* tee_identity,
                                         const char* report_type,
                                         const char* report_hex_nonce,
                                         const char* report_params_buf,
                                         const unsigned int report_params_len,
                                         char* auth_report_buf,
                                         unsigned int* auth_report_len) {
  TEE_CHECK_VALIDBUF(auth_report_buf, *auth_report_len);
  UaReportGenerationParameters param;
  param.tee_identity = SAFESTR(tee_identity);
  param.report_type = SAFESTR(report_type);
  param.report_hex_nonce = SAFESTR(report_hex_nonce);
  if (report_params_buf && report_params_len) {
    std::string report_params(report_params_buf, report_params_len);
    JSON2PB(report_params, &param.others);
  }

  std::string auth_report_json;
  TEE_CATCH_RETURN(UaGenerateAuthReportJson(&param, &auth_report_json));
  if (*auth_report_len <= auth_report_json.size()) {
    TEE_LOG_ERROR("Too small auth report buf buf_size: %d, report_size: %ld\n",
                  *auth_report_len, auth_report_json.size());
    return TEE_ERROR_RA_SMALLER_REPORT_BUFFER;
  }

  *auth_report_len = auth_report_json.size();
  memcpy(auth_report_buf, auth_report_json.data(), *auth_report_len);
  return TEE_SUCCESS;
}

/// C API for unified attestation submodule reports verification
int UnifiedAttestationVerifySubReports(const char* tee_identity,
                                       const char** auth_json_str,
                                       const unsigned int auth_json_count,
                                       const char** policy_json_str,
                                       const unsigned int policy_json_count,
                                       char* nested_reports_json_str,
                                       unsigned int* nested_reports_json_len) {
  // Convert to C++ parameters
  kubetee::UnifiedAttestationAuthReports auth_reports;
  for (unsigned int i = 0; i < auth_json_count; i++) {
    auth_reports.add_reports(SAFESTR(auth_json_str[i]));
  }

  kubetee::UnifiedAttestationPolicy policy;
  for (unsigned int i = 0; i < policy_json_count; i++) {
    JSON2PB(SAFESTR(policy_json_str[i]), policy.add_nested_policies());
  }

  // Call the C++ verify interface, which has trused and untrusted implements
  std::string nested_reports_json;
  std::string tee_identity_str = SAFESTR(tee_identity);
  TEE_CATCH_RETURN(UaGenerationVerifySubReports(tee_identity_str, auth_reports,
                                                policy, &nested_reports_json));

  // Copy to c buffer
  if (*nested_reports_json_len <= nested_reports_json.size()) {
    ELOG_ERROR("Too smaller nested reports buf, %ld required",
               nested_reports_json.size());
    return TEE_ERROR_RA_VERIFY_NESTED_REPORTS_SMALLER_BUFFER;
  }
  *nested_reports_json_len = nested_reports_json.size();
  memcpy(nested_reports_json_str, nested_reports_json.data(),
         nested_reports_json.size());

  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
