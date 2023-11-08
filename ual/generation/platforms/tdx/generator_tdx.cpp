/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 * Copyright (c) 2023-2024 Ant Group
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>  // for mmap
#include <unistd.h>    // for sleep() function
#include <algorithm>
#include <string>
#include <vector>

#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/sm3.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"
#include "attestation/verification/ua_verification.h"

#include "generation/platforms/tdx/generator_tdx.h"

#ifdef __cplusplus
extern "C" {
#endif

static TeeErrorCode get_tdx_attestation_report(const uint8_t* user_data_buf,
                                               int user_data_len,
                                               uint8_t* report_buf,
                                               int* report_size) {
  // dummy code here, to be implemented
  memcpy(report_buf, user_data_buf, *report_size);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationGeneratorTdx::Initialize(
    const std::string& tee_identity) {
  if (tee_identity.empty()) {
    TEE_LOG_ERROR("Enclave has not been created successfully");
    return TEE_ERROR_RA_NOTINITIALIZED;
  }
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorTdx::GetQuote(
    const UaReportGenerationParameters& param, std::string* pquote_b64) {
  // Prepare the user data buffer
  uint8_t report_data_buf[TDX_ATTESTATION_USER_DATA_SIZE] = {
      0,
  };
  TEE_CHECK_RETURN(PrepareReportData(param, report_data_buf,
                                     TDX_ATTESTATION_USER_DATA_SIZE));
  // Replace the higher 32 bytes by HASH UAK public key
  if (param.others.pem_public_key().empty() && !UakPublic().empty()) {
    kubetee::common::DataBytes pubkey(UakPublic());
    pubkey.ToSHA256().Export(report_data_buf + kSha256Size, kSha256Size).Void();
  }

  // Get the TDX report
  uint8_t report_buf[TDX_ATTESTATION_USER_DATA_SIZE];
  int report_size = TDX_ATTESTATION_USER_DATA_SIZE;
  TEE_CHECK_RETURN(get_tdx_attestation_report(report_data_buf,
                                              TDX_ATTESTATION_USER_DATA_SIZE,
                                              report_buf, &report_size));

  kubetee::common::DataBytes b64_quote;
  b64_quote.SetValue(RCAST(uint8_t*, &report_buf), sizeof(report_buf));
  pquote_b64->assign(b64_quote.ToBase64().GetStr());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorTdx::CreateBgcheckReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // Get attestation quote
  kubetee::IntelTdxReport tdx_report;
  TEE_CHECK_RETURN(GetQuote(param, tdx_report.mutable_b64_quote()));

  // Make the final report with quote only
  report->set_str_tee_platform(kUaPlatformTdx);
  report->set_str_report_type(kUaReportTypeBgcheck);
  PB2JSON(tdx_report, report->mutable_json_report());

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorTdx::CreatePassportReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // Get attestation quote
  kubetee::IntelTdxReport tdx_report;
  TEE_CHECK_RETURN(GetQuote(param, tdx_report.mutable_b64_quote()));

  // Make the final report with quote only
  report->set_str_tee_platform(kUaPlatformTdx);
  report->set_str_report_type(kUaReportTypePassport);
  PB2JSON(tdx_report, report->mutable_json_report());

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorTdx::VerifySubReportsTrusted(
    const kubetee::UnifiedAttestationAuthReports& auth_reports,
    const kubetee::UnifiedAttestationPolicy& policy,
    std::string* results_json) {
  TEE_CHECK_RETURN(UaVerifySubReports(auth_reports, policy, results_json));
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
