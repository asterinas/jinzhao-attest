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

#ifdef __cplusplus
}
#endif
