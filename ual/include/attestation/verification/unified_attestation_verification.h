#ifndef UAL_INCLUDE_ATTESTATION_VERIFICATION_UNIFIED_ATTESTATION_VERIFICATION_H_
#define UAL_INCLUDE_ATTESTATION_VERIFICATION_UNIFIED_ATTESTATION_VERIFICATION_H_

#include "attestation/common/attestation.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief C API for authentication unified attestation report verification
///
/// @param auth_json_str: The serialized JSON string of
///                       UnifiedAttestationAuthReport.
/// @param auth_json_len: The length of serialized JSON string of
///                       UnifiedAttestationAuthReport.
/// @param policy_json_str: The serialized JSON string for
///                         UnifiedAttestationPolicy.
/// @param policy_json_len: The length of serialized JSON string for
///                         UnifiedAttestationPolicy.
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationVerifyAuthReport(
    const char* auth_json_str,
    const unsigned int auth_json_len,
    const char* policy_json_str,
    const unsigned int policy_json_len);

/// @brief C API for unified attestation report verification
///
/// @param report_json_str: The serialized JSON string of
///                         UnifiedAttestationReport.
/// @param report_json_len: The length of serialized JSON string of
///                         UnifiedAttestationReport.
/// @param policy_json_str: The serialized JSON string for
///                         UnifiedAttestationPolicy.
/// @param policy_json_len: The length of serialized JSON string for
///                         UnifiedAttestationPolicy.
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationVerifyReport(const char* report_json_str,
                                          const unsigned int report_json_len,
                                          const char* policy_json_str,
                                          const unsigned int policy_json_len);

/// @brief C API to get attester attributes in authentication report
///
/// @param auth_json_str: The serialized JSON string of
///                       UnifiedAttestationAuthReport.
/// @param auth_json_len: The length of serialized JSON string of
///                       UnifiedAttestationAuthReport.
/// @param attr_json_str: The serialized JSON string for
///                       UnifiedAttestationAttributes.
/// @param attr_json_len: The length of serialized JSON string for
///                       UnifiedAttestationAttributes.
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationGetAuthReportAttr(const char* auth_json_str,
                                               const unsigned int auth_json_len,
                                               char* attr_json_str,
                                               unsigned int* attr_json_len);

/// @brief C API to get attester attributes in unified attestation report
///
/// @param report_json_str: The serialized JSON string of
///                         UnifiedAttestationReport.
/// @param report_json_len: The length of serialized JSON string of
///                         UnifiedAttestationReport.
/// @param attr_json_str: The serialized JSON string for
///                       UnifiedAttestationAttributes.
/// @param attr_json_len: The length of serialized JSON string for
///                       UnifiedAttestationAttributes.
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationGetReportAttr(const char* report_json_str,
                                           const unsigned int report_json_len,
                                           char* attr_json_str,
                                           unsigned int* attr_json_len);

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_VERIFICATION_UNIFIED_ATTESTATION_VERIFICATION_H_
