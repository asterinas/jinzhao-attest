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
#include "attestation/platforms/tdx_report_body.h"
#include "attestation/verification/ua_verification.h"

#include "generation/platforms/tdx/generator_tdx.h"

#include "network/pccs_client.h"

#include "./tdx_attest.h"

#ifdef __cplusplus
extern "C" {
#endif

static TeeErrorCode get_tdx_attestation_quote(tdx_report_data_t* report_data,
                                              std::string* tdx_quote) {
  tdx_report_t tdx_report = {{0}};
  int ret = tdx_att_get_report(report_data, &tdx_report);
  if (ret) {
    TEE_LOG_ERROR("tdx_att_get_report failed: 0x%X", ret);
    return ret;
  }

  // generation quote
  tdx_uuid_t selected_att_key_id = {{0}};
  uint8_t* p_quote_buf = nullptr;
  uint32_t quote_size = 0;
  ret = tdx_att_get_quote(report_data, NULL, 0, &selected_att_key_id,
                          &p_quote_buf, &quote_size, 0);
  if ((ret == TDX_ATTEST_SUCCESS) && p_quote_buf) {
    TEE_LOG_DEBUG("get_tdx_attestation_quote success");
    tdx_quote->assign(RCAST(char*, p_quote_buf), quote_size);
  } else {
    TEE_LOG_ERROR("tdx_att_get_quote failed: 0x%X", ret);
  }
  if (p_quote_buf) {
    tdx_att_free_quote(p_quote_buf);
  }
  return ret;
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
    const UaReportGenerationParameters& param, std::string* quote) {
  // Check the report data size
  size_t report_data_size = sizeof(tdx_report_data_t);
  if (report_data_size != TDX_ATTESTATION_REPORT_DATA_SIZE) {
    TEE_LOG_ERROR("Unexprect report data struct size: %d", report_data_size);
    return TEE_ERROR_RA_REPORT_DATA_SIZE;
  }

  // Prepare the report data
  tdx_report_data_t report_data;
  TEE_CHECK_RETURN(PrepareReportData(param, report_data.d, report_data_size));
  // Replace the higher 32 bytes by HASH UAK public key
  if (param.others.pem_public_key().empty() && !UakPublic().empty()) {
    kubetee::common::DataBytes pubkey(UakPublic());
    pubkey.ToSHA256().Export(report_data.d + kSha256Size, kSha256Size).Void();
  }

  // Get TDX quote
  TEE_CHECK_RETURN(get_tdx_attestation_quote(&report_data, quote));

  // Parse the attester attributes
  kubetee::common::platforms::TdxReportBodyParser report_body_parser;
  TEE_CHECK_RETURN(report_body_parser.ParseReportBody(*quote, &attributes_));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorTdx::CreateBgcheckReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // Get attestation quote
  std::string quote;
  TEE_CHECK_RETURN(GetQuote(param, &quote));

  // Convent quote to base64 format
  kubetee::IntelTdxReport tdx_report;
  kubetee::common::DataBytes quote_b64(quote);
  tdx_report.set_b64_quote(quote_b64.ToBase64().GetStr());

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
  std::string quote;
  TEE_CHECK_RETURN(GetQuote(param, &quote));

  // Get the quote verification collateral
  kubetee::SgxQlQveCollateral collateral;
  PccsClient pccs_client;
  TEE_CHECK_RETURN(pccs_client.GetSgxCollateral(quote, &collateral));

  // Convent quote to base64 format and prepare DcapReport
  kubetee::IntelTdxReport tdx_report;
  kubetee::common::DataBytes quote_b64(quote);
  tdx_report.set_b64_quote(quote_b64.ToBase64().GetStr());
  TEE_LOG_TRACE("QUOTE BASE64[%lu]: %s", tdx_report.b64_quote().size(),
                tdx_report.b64_quote().c_str());
  PB2JSON(collateral, tdx_report.mutable_json_collateral());

  // Make the final report with quote only
  report->set_str_tee_platform(kUaPlatformTdx);
  report->set_str_report_type(kUaReportTypePassport);
  PB2JSON(tdx_report, report->mutable_json_report());

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
