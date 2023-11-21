#include <string>

#include "attestation/common/bytes.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"
#include "attestation/verification/core/verifier.h"
#include "attestation/verification/ua_verification.h"

#ifdef __cplusplus
extern "C" {
#endif

/// C++ API for unified attestation report verification
TeeErrorCode UaVerifyAuthReport(
    const kubetee::UnifiedAttestationAuthReport& auth,
    const kubetee::UnifiedAttestationPolicy& policy) {
  // Assume the verification policy is prepared in caller side
  // But force to use the public key in auth report
  kubetee::UnifiedAttestationPolicy new_policy;
  new_policy.CopyFrom(policy);
  new_policy.mutable_pem_public_key()->assign(auth.pem_public_key());

  kubetee::attestation::AttestationVerifier verifier;
  TEE_CHECK_RETURN(verifier.Initialize(auth.report()));
  TEE_CHECK_RETURN(verifier.Verify(new_policy));
  return TEE_SUCCESS;
}

TeeErrorCode UaVerifyReport(const kubetee::UnifiedAttestationReport& report,
                            const kubetee::UnifiedAttestationPolicy& policy) {
  // Assume the verification policy is prepared in caller side
  kubetee::attestation::AttestationVerifier verifier;
  TEE_CHECK_RETURN(verifier.Initialize(report));
  TEE_CHECK_RETURN(verifier.Verify(policy));
  return TEE_SUCCESS;
}

TeeErrorCode UaVerifyAuthReportJson(const std::string& auth_json,
                                    const std::string& policy_json) {
  // Parse the protobuf serialized auth and policy JSON string
  kubetee::UnifiedAttestationAuthReport auth;
  JSON2PB(auth_json, &auth);
  kubetee::UnifiedAttestationPolicy policy;
  JSON2PB(policy_json, &policy);
  policy.mutable_pem_public_key()->assign(auth.pem_public_key());

  TEE_CHECK_RETURN(UaVerifyReport(auth.report(), policy));
  return TEE_SUCCESS;
}

TeeErrorCode UaVerifyReportJson(const std::string& report_json,
                                const std::string& policy_json) {
  // Parse the protobuf serialized auth JSON string
  kubetee::UnifiedAttestationReport report;
  JSON2PB(report_json, &report);
  kubetee::UnifiedAttestationPolicy policy;
  JSON2PB(policy_json, &policy);

  TEE_CHECK_RETURN(UaVerifyReport(report, policy));
  return TEE_SUCCESS;
}

/// C++ API to get attester attributes in attestation report
TeeErrorCode UaGetAuthReportAttr(
    const kubetee::UnifiedAttestationAuthReport& auth,
    kubetee::UnifiedAttestationAttributes* attr) {
  kubetee::attestation::AttestationVerifier verifier;
  TEE_CHECK_RETURN(verifier.Initialize(auth.report()));
  TEE_CHECK_RETURN(verifier.GetAttesterAttr(attr));
  return TEE_SUCCESS;
}

TeeErrorCode UaGetReportAttr(const kubetee::UnifiedAttestationReport& report,
                             kubetee::UnifiedAttestationAttributes* attr) {
  kubetee::attestation::AttestationVerifier verifier;
  TEE_CHECK_RETURN(verifier.Initialize(report));
  TEE_CHECK_RETURN(verifier.GetAttesterAttr(attr));
  return TEE_SUCCESS;
}

TeeErrorCode UaGetAuthReportAttrJson(const std::string& auth_json,
                                     std::string* attr_json) {
  // Parse the protobuf serialized auth JSON string
  kubetee::UnifiedAttestationAuthReport auth;
  JSON2PB(auth_json, &auth);

  kubetee::UnifiedAttestationAttributes attr;
  TEE_CHECK_RETURN(UaGetAuthReportAttr(auth, &attr));
  PB2JSON(attr, attr_json);
  return TEE_SUCCESS;
}

TeeErrorCode UaGetReportAttrJson(const std::string& report_json,
                                 std::string* attr_json) {
  // Parse the protobuf serialized auth JSON string
  kubetee::UnifiedAttestationReport report;
  JSON2PB(report_json, &report);

  kubetee::UnifiedAttestationAttributes attr;
  TEE_CHECK_RETURN(UaGetReportAttr(report, &attr));
  PB2JSON(attr, attr_json);
  return TEE_SUCCESS;
}

/// @brief C++ API to verify policy itself
TeeErrorCode UaVerifyPolicy(
    const kubetee::UnifiedAttestationPolicy& actual_policy,
    const kubetee::UnifiedAttestationPolicy& expected_policy) {
  TEE_CHECK_RETURN(
      kubetee::attestation::AttestationVerifierInterface::VerifyPolicy(
          actual_policy, expected_policy));
  return TEE_SUCCESS;
}

TeeErrorCode UaVerifyPolicyJson(const std::string& actual_policy_json,
                                const std::string& expected_policy_json) {
  kubetee::UnifiedAttestationPolicy actual_policy;
  kubetee::UnifiedAttestationPolicy expected_policy;
  JSON2PB(actual_policy_json, &actual_policy);
  JSON2PB(expected_policy_json, &expected_policy);

  TEE_CHECK_RETURN(UaVerifyPolicy(actual_policy, expected_policy));
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
