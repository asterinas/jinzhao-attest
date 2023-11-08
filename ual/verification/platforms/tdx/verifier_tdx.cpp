/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 * Copyright (c) 2022 Ant Group
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/scope.h"
#include "attestation/common/type.h"

#include "verification/platforms/tdx/verifier_tdx.h"

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationVerifierTdx::Initialize(
    const kubetee::UnifiedAttestationReport& report) {
  if (!report.json_nested_reports().empty()) {
    JSON2PB(report.json_nested_reports(), &nested_reports_);
  }
  verify_spid_ = false;
  report_type_ = report.str_report_type();

  // Check the platform
  if (report.str_tee_platform() != kUaPlatformTdx) {
    ELOG_ERROR("It's not %s platfrom, input platform is [%s]", kUaPlatformTdx,
               report.str_tee_platform().c_str());
    return TEE_ERROR_RA_VERIFY_ATTR_TEE_PLATFORM;
  }

  // Get the report data, which is serialized json string
  kubetee::IntelTdxReport tdx_report;
  JSON2PB(report.json_report(), &tdx_report);
  b64_report_ = tdx_report.b64_quote();
  report_.SetValue(b64_report_);
  TEE_CHECK_RETURN(report_.FromBase64().GetError());

  // Parse the attester attributes in TDX report
  TEE_CHECK_RETURN(ParseAttributes());

  // Set the platform for UnifiedAttestationAttributes
  attributes_.set_str_tee_platform(kUaPlatformTdx);

  // Set the hex_spid empty
  attributes_.set_hex_spid("");

  // Show the attester attributes in report
  ELOG_DEBUG("Initialize TDX verifier successfully");
  TEE_CHECK_RETURN(ShowAttesterAttributes());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierTdx::VerifyPlatform(
    const kubetee::UnifiedAttestationAttributes& attr) {
  TEE_UNREFERENCED_PARAMETER(attr);

  // Check the report type if the BackgroundCheck type return unsupport
  if (report_type_ == kUaReportTypeBgcheck) {
    ELOG_ERROR("BackgroundCheck type is not supported to be verified");
    return TEE_ERROR_RA_VERIFY_NEED_RERERENCE_DATA;
  }

  // TEE_CHECK_RETURN(VerifyCertChain(cert_chain_, report));
  // TEE_CHECK_RETURN(VerifyReportSignature(report));
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierTdx::GetReportQuote(std::string* quote) {
  quote->assign(b64_report_);
  return TEE_SUCCESS;
}

/// Parse the attestation attributes fields in TDX report
TeeErrorCode AttestationVerifierTdx::ParseAttributes() {
  kubetee::common::DataBytes userdata(report_.data(), kSha256Size);
  attributes_.set_hex_user_data(userdata.ToHexStr().GetStr());

  // Export the higher 32 bytes as public key hash
  const uint8_t* pubkey_hash_start = report_.data() + kSha256Size;
  kubetee::common::DataBytes pubhash(pubkey_hash_start, kSha256Size);
  attributes_.set_hex_hash_or_pem_pubkey(pubhash.ToHexStr().GetStr());

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
