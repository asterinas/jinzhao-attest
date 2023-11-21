#ifndef UAL_INCLUDE_ATTESTATION_VERIFICATION_UA_VERIFICATION_H_
#define UAL_INCLUDE_ATTESTATION_VERIFICATION_UA_VERIFICATION_H_

#include <string>

#include "attestation/common/attestation.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief C++ API for unified attestation report verification
///
/// @param auth: the unified attestation authentication report
/// @param policy: the policy for verification
///
/// @return 0 means success or other error code
///
extern TeeErrorCode UaVerifyAuthReport(
    const kubetee::UnifiedAttestationAuthReport& auth,
    const kubetee::UnifiedAttestationPolicy& policy);

extern TeeErrorCode UaVerifyReport(
    const kubetee::UnifiedAttestationReport& report,
    const kubetee::UnifiedAttestationPolicy& policy);

extern TeeErrorCode UaVerifyAuthReportJson(const std::string& auth_json,
                                           const std::string& policy_json);

extern TeeErrorCode UaVerifyReportJson(const std::string& report_json,
                                       const std::string& policy_json);

/// @brief C++ API to get attester attributes in attestation report
///
extern TeeErrorCode UaGetAuthReportAttr(
    const kubetee::UnifiedAttestationAuthReport& auth,
    kubetee::UnifiedAttestationAttributes* attr);

extern TeeErrorCode UaGetReportAttr(
    const kubetee::UnifiedAttestationReport& report,
    kubetee::UnifiedAttestationAttributes* attr);

extern TeeErrorCode UaGetAuthReportAttrJson(const std::string& auth_json,
                                            std::string* attr_json);

extern TeeErrorCode UaGetReportAttrJson(const std::string& report_json,
                                        std::string* attr_json);

/// @brief C++ API to verify policy itself
///
/// This happens when policy comes from unstusted administrator or conf file
///
extern TeeErrorCode UaVerifyPolicy(
    const kubetee::UnifiedAttestationPolicy& actual_policy,
    const kubetee::UnifiedAttestationPolicy& expected_policy);

extern TeeErrorCode UaVerifyPolicyJson(const std::string& actual_policy_json,
                                       const std::string& expected_policy_json);

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_VERIFICATION_UA_VERIFICATION_H_
