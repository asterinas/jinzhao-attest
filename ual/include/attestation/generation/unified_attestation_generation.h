#ifndef UAL_INCLUDE_ATTESTATION_GENERATION_UNIFIED_ATTESTATION_GENERATION_H_
#define UAL_INCLUDE_ATTESTATION_GENERATION_UNIFIED_ATTESTATION_GENERATION_H_

#include "attestation/common/attestation.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief C API for unified attestation report generation
/// @param tee_identity: The identity of TEE or TA instance
/// @param report_type: Type of report, "BackgroundCheck"|"Passport"|"Uas"
/// @param report_hex_nonce: Provide freshness if necessary.
///                      It's string at most 32 Bytes.
/// @param report_params_buf: The other report generation parameters buffer.
/// @param report_params_len: The length of other report generation parameters.
/// @param report_josn_buf: The output serialized JSON string of the report
/// @param report_josn_len: The maximal JSON report buffer size as input,
///                         and the real JSON report string size as output.
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationGenerateReport(
    const char* tee_identity,
    const char* report_type,
    const char* report_hex_nonce,
    const char* report_params_buf,
    const unsigned int report_params_len,
    char* report_json_buf,
    unsigned int* report_json_len);

/// @brief C API for unified attestation authentication report generation
///
/// @param tee_identity: The identity of TEE or TA instance
/// @param report_type: Type of report, "BackgroundCheck"|"Passport"|"Uas"
/// @param report_hex_nonce: Provide freshness if necessary.
///                      It's string at most 32 Bytes.
/// @param report_params_buf: The other report generation parameters buffer.
/// @param report_params_len: The length of other report generation parameters.
/// @param auth_report_buf: The output serialized JSON string of
///                         UnifiedAttestationAuthReport.
/// @param auth_report_len: The maximal JSON auth report buffer size as input,
///                         and the real JSON auth report string size as output.
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationGenerateAuthReport(
    const char* tee_identity,
    const char* report_type,
    const char* report_hex_nonce,
    const char* report_params_buf,
    const unsigned int report_params_len,
    char* auth_report_buf,
    unsigned int* auth_report_len);

/// @brief C API for verifying nested submodule attester report
///
/// @param tee_identity: The identity of TEE or TA instance.
/// @param auth_json_str: This is a char* array, each item points to the JSON
///                       serialized string of UnifiedAttestationAuthReport.
/// @param auth_json_count: The count of JSON UnifiedAttestationAuthReport.
/// @param policy_json_str: This is a char* array, each item is used to verify
///                         a auth report, and points to the JSON serialized
///                         string of UnifiedAttestationNestedPolicy.
///                         Full UnifiedAttestationPolicy is composed inside
///                         this function to call other under-layer function.
/// @param policy_json_count: The count of JSON UnifiedAttestationNestedPolicy.
/// @param nested_reports_json_str: The output buffer for JSON serialized
///                                 string of UnifiedAttestationNestedReports
/// @param nested_reports_json_len: The input max and output real lenght of
///                                 nested reports buffer.
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationVerifySubReports(
    const char* tee_identity,
    const char** auth_json_str,
    const unsigned int auth_json_count,
    const char** policy_json_str,
    const unsigned int policy_json_count,
    char* nested_reports_json_str,
    unsigned int* nested_reports_json_len);

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_GENERATION_UNIFIED_ATTESTATION_GENERATION_H_
