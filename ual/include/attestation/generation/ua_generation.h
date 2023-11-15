#ifndef UAL_INCLUDE_ATTESTATION_GENERATION_UA_GENERATION_H_
#define UAL_INCLUDE_ATTESTATION_GENERATION_UA_GENERATION_H_

#include <string>

#include "attestation/generation/core/generator_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

using kubetee::attestation::UaReportGenerationParameters;

/// @brief C++ API for unified attestation report generation
/// @param[in]  param: how to generate the report
/// @param[out] report: the UnifiedAttestationReport which is generated
///
/// @return 0 means success or other error code
///
extern TeeErrorCode UaGenerateReport(UaReportGenerationParameters* param,
                                     kubetee::UnifiedAttestationReport* report);

extern TeeErrorCode UaGenerateReportJson(UaReportGenerationParameters* param,
                                         std::string* report_json);

/// @brief C++ API for unified attestation report generation
/// @param[in]  param: how to generate the report
/// @param[out] auth: generated authentication report
///
/// @return 0 means success or other error code
///
/// Only the AuthReport type report has public key to verify nested report
extern TeeErrorCode UaGenerateAuthReport(
    UaReportGenerationParameters* param,
    kubetee::UnifiedAttestationAuthReport* auth);

extern TeeErrorCode UaGenerateAuthReportJson(
    UaReportGenerationParameters* param, std::string* json_auth_report);

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_GENERATION_UA_GENERATION_H_
