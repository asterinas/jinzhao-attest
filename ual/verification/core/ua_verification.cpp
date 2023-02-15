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

/// C++ API to verify the reports of submodule attesters
TeeErrorCode UaVerifySubReports(
    const kubetee::UnifiedAttestationAuthReports& auth_reports,
    const kubetee::UnifiedAttestationPolicy& policy,
    std::string* nested_reports_json) {
  if (auth_reports.reports_size() != policy.nested_policies_size()) {
    ELOG_ERROR("%d reports mismatch %d policies", auth_reports.reports_size(),
               policy.nested_policies_size());
    return TEE_ERROR_RA_VERIFY_NESTED_POLICIES_SIZE;
  }

  kubetee::UnifiedAttestationNestedResults results;
  for (int i = 0; i < auth_reports.reports_size(); i++) {
    kubetee::UnifiedAttestationAuthReport auth;
    JSON2PB(auth_reports.reports()[i], &auth);
    kubetee::UnifiedAttestationPolicy verify_policy;
    verify_policy.set_pem_public_key(auth.pem_public_key());
    const kubetee::UnifiedAttestationNestedPolicy& nested_policy =
        policy.nested_policies()[i];
    for (int j = 0; j < nested_policy.sub_attributes_size(); j++) {
      verify_policy.add_main_attributes()->CopyFrom(
          nested_policy.sub_attributes()[j]);
    }
    kubetee::attestation::AttestationVerifier verifier;
    TEE_CHECK_RETURN(verifier.Initialize(auth.report()));
    TEE_CHECK_RETURN(verifier.Verify(verify_policy));
    TEE_CHECK_RETURN(verifier.GetAttesterAttr(results.add_results()));
  }

  kubetee::UnifiedAttestationNestedReports nested_reports;
  PB2JSON(results, nested_reports.mutable_json_nested_results());

  // Add the signature of submodule enclaves
  std::string signature;
  TEE_CHECK_RETURN(kubetee::common::RsaCrypto::Sign(
      UakPrivate(), nested_reports.json_nested_results(), &signature));
  kubetee::common::DataBytes b64_signature(signature);
  nested_reports.set_b64_nested_signature(b64_signature.ToBase64().GetStr());

  PB2JSON(nested_reports, nested_reports_json);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
