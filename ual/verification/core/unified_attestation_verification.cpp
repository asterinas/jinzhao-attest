#include <string>

#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"
#include "attestation/verification/core/verifier.h"
#include "attestation/verification/ua_verification.h"
#include "attestation/verification/unified_attestation_verification.h"

#ifdef __cplusplus
extern "C" {
#endif

/// C API for unified attestation report verification
int UnifiedAttestationVerifyAuthReport(const char* auth_json_str,
                                       const unsigned int auth_json_len,
                                       const char* policy_json_str,
                                       const unsigned int policy_json_len) {
  TEE_CHECK_VALIDBUF(auth_json_str, auth_json_len);
  TEE_CHECK_VALIDBUF(policy_json_str, policy_json_len);

  // Prepare the serialized auth and policy json string
  std::string auth_json(auth_json_str, auth_json_len);
  std::string policy_json(policy_json_str, policy_json_len);

  // Verify the remote attestation authentication report
  TEE_CATCH_RETURN(UaVerifyAuthReportJson(auth_json, policy_json));
  return TEE_SUCCESS;
}

int UnifiedAttestationVerifyReport(const char* report_json_str,
                                   const unsigned int report_json_len,
                                   const char* policy_json_str,
                                   const unsigned int policy_json_len) {
  TEE_CHECK_VALIDBUF(report_json_str, report_json_len);
  TEE_CHECK_VALIDBUF(policy_json_str, policy_json_len);

  // Prepare the serialized report and policy json string
  std::string report_json(report_json_str, report_json_len);
  std::string policy_json(policy_json_str, policy_json_len);

  // Verify the remote attestation report
  TEE_CATCH_RETURN(UaVerifyReportJson(report_json, policy_json));
  return TEE_SUCCESS;
}

/// C API for unified attestation report information
int UnifiedAttestationGetAuthReportAttr(const char* auth_json_str,
                                        const unsigned int auth_json_len,
                                        char* attr_json_str,
                                        unsigned int* attr_json_len) {
  TEE_CHECK_VALIDBUF(auth_json_str, auth_json_len);
  TEE_CHECK_VALIDBUF(attr_json_str, *attr_json_len);

  // Prepare the protobuf serialized auth report
  std::string auth_json(auth_json_str, auth_json_len);

  std::string attr_json;
  TEE_CATCH_RETURN(UaGetAuthReportAttrJson(auth_json, &attr_json));
  if (*attr_json_len <= attr_json.size()) {
    ELOG_ERROR("Too smaller enclave info buf, %ld required", attr_json.size());
    return TEE_ERROR_RA_VERIFY_SMALLER_INFO_BUFFER;
  }

  *attr_json_len = attr_json.size();
  memcpy(attr_json_str, attr_json.data(), *attr_json_len);
  return TEE_SUCCESS;
}

int UnifiedAttestationGetReportAttr(const char* report_json_str,
                                    const unsigned int report_json_len,
                                    char* attr_json_str,
                                    unsigned int* attr_json_len) {
  TEE_CHECK_VALIDBUF(report_json_str, report_json_len);
  TEE_CHECK_VALIDBUF(attr_json_str, *attr_json_len);

  // Prepare the protobuf serialized report
  std::string report_json(report_json_str, report_json_len);

  std::string attr_json;
  TEE_CATCH_RETURN(UaGetReportAttrJson(report_json, &attr_json));
  if (*attr_json_len <= attr_json.size()) {
    ELOG_ERROR("Too smaller enclave info buf, %ld required", attr_json.size());
    return TEE_ERROR_RA_VERIFY_SMALLER_INFO_BUFFER;
  }

  *attr_json_len = attr_json.size();
  memcpy(attr_json_str, attr_json.data(), *attr_json_len);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
