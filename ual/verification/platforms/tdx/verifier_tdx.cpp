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
#include "attestation/platforms/tdx_report_body.h"

#include "./sgx_dcap_qv_internal.h"
#include "./sgx_qve_header.h"

#include "verification/platforms/tdx/verifier_tdx.h"

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationVerifierTdx::Initialize(
    const kubetee::UnifiedAttestationReport& report) {
  if (!report.json_nested_reports().empty()) {
    JSON2PB(report.json_nested_reports(), &nested_reports_);
  }
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
  b64_quote_body_ = tdx_report.b64_quote();
  kubetee::common::DataBytes b64_quote(b64_quote_body_);
  quote_.assign(b64_quote.FromBase64().GetStr());
  if (!tdx_report.json_collateral().empty()) {
    JSON2PB(tdx_report.json_collateral(), &collateral_);
  }

  // Parse the attester attributes in TDX report
  TEE_CHECK_RETURN(ParseQuoteReportBody());

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

#ifndef SGX_MODE_SIM
  // Check the report type if the BackgroundCheck type return unsupport
  if (report_type_ == kUaReportTypeBgcheck) {
    ELOG_ERROR("BackgroundCheck type is not supported to be verified");
    return TEE_ERROR_RA_VERIFY_NEED_RERERENCE_DATA;
  }

  // Verify the DCAP report signature and status,
  TEE_CHECK_RETURN(QvlVerifyReport(collateral_, RCCAST(uint8_t*, quote_.data()),
                                   quote_.size()));
#endif

  ELOG_DEBUG("Verify TDX Platform Successfully!");
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierTdx::GetReportQuote(std::string* quote) {
  quote->assign(b64_quote_body_);
  return TEE_SUCCESS;
}

/// Parse the attestation attributes fields in TDX report
TeeErrorCode AttestationVerifierTdx::ParseQuoteReportBody() {
  kubetee::common::platforms::TdxReportBodyParser report_body_parser;
  TEE_CHECK_RETURN(report_body_parser.ParseReportBody(quote_, &attributes_));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierTdx::SetCollateral(const char* n,
                                                   const std::string& s,
                                                   char** d,
                                                   uint32_t* l) {
  if (s.empty()) {
    ELOG_ERROR("Invlaid collateral data: %s", n);
    return TEE_ERROR_RA_VERIFY_INVALID_COLLATERAL_DATA;
  }
  *d = CCAST(char*, s.data());

  // +1 is the workaround for the code in qvl, size should include the end '\0'
  // #define IS_IN_ENCLAVE_POINTER(p, size)
  //    (p && (strnlen(p, size) == size - 1) && sgx_is_within_enclave(p, size))
  *l = SCAST(uint32_t, s.size() + 1);
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierTdx::InitializeCollateralData(
    const kubetee::SgxQlQveCollateral& collateral,
    sgx_ql_qve_collateral_t* collateral_data) {
  collateral_data->version = collateral.version();
  collateral_data->tee_type = collateral.tee_type();

  // Set the sgx_ql_qve_collateral_t with data pointer and size
  // clang-format off
  TEE_CHECK_RETURN(SetCollateral("pck_crl_issuer_chain",
      collateral.pck_crl_issuer_chain(),
      &(collateral_data->pck_crl_issuer_chain),
      &(collateral_data->pck_crl_issuer_chain_size)));
  TEE_CHECK_RETURN(SetCollateral("root_ca_crl",
      collateral.root_ca_crl(),
      &(collateral_data->root_ca_crl),
      &(collateral_data->root_ca_crl_size)));
  TEE_CHECK_RETURN(SetCollateral("pck_crl",
      collateral.pck_crl(),
      &(collateral_data->pck_crl),
      &(collateral_data->pck_crl_size)));
  TEE_CHECK_RETURN(SetCollateral("tcb_info_issuer_chain",
      collateral.tcb_info_issuer_chain(),
      &(collateral_data->tcb_info_issuer_chain),
      &(collateral_data->tcb_info_issuer_chain_size)));
  TEE_CHECK_RETURN(SetCollateral("tcb_info",
      collateral.tcb_info(),
      &(collateral_data->tcb_info),
      &(collateral_data->tcb_info_size)));
  TEE_CHECK_RETURN(SetCollateral("qe_identity_issuer_chain",
      collateral.qe_identity_issuer_chain(),
      &(collateral_data->qe_identity_issuer_chain),
      &(collateral_data->qe_identity_issuer_chain_size)));
  TEE_CHECK_RETURN(SetCollateral("qe_identity",
      collateral.qe_identity(),
      &(collateral_data->qe_identity),
      &(collateral_data->qe_identity_size)));
  // clang-format on

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierTdx::QvlInitializeSupplementalData(
    std::string* supplemental) {
  uint32_t supplemental_data_size = 0;
  quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
  dcap_ret = sgx_qvl_get_quote_supplemental_data_size(&supplemental_data_size);
  if (dcap_ret != SGX_QL_SUCCESS) {
    ELOG_ERROR("Fail to get supplemental data size: 0x%04x", dcap_ret);
    return TEE_ERROR_RA_VERIFY_GET_SUPPLEMENTAL_SIZE;
  }

  if (supplemental_data_size != sizeof(sgx_ql_qv_supplemental_t)) {
    // Size is not same with header definition in SGX SDK, please make sure
    // you are using same version of SGX SDK and DCAP QVL.
    ELOG_ERROR("Warning: Invalid supplemental data size returned");
    return TEE_ERROR_RA_VERIFY_INVALID_SUPPLEMENTAL_SIZE;
  }

  supplemental->resize(supplemental_data_size, '\0');
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierTdx::QvlVerifyReport(
    const kubetee::SgxQlQveCollateral& collateral,
    const uint8_t* pquote,
    const size_t quote_size) {
  // Initialize the collateral data
  sgx_ql_qve_collateral_t collateral_data;
  TEE_CHECK_RETURN(InitializeCollateralData(collateral, &collateral_data));

  // Get the supplemental data size
  // std::string supplemental;
  // TEE_CHECK_RETURN(QvlInitializeSupplementalData(&supplemental));

  // set current time. Using a small time number as workaround here.
  // In production mode a trusted time should be used.
  time_t current_time = 1;  // time(NULL);

  // call DCAP quote verify library for quote verification
  // here you can choose 'trusted' or 'untrusted' quote verification by
  // specifying parameter '&qve_report_info' if '&qve_report_info' is NOT
  // NULL, this API will call Intel QvE to verify quote if '&qve_report_info'
  // is NULL, this API will call 'untrusted quote verify lib' to verify quote,
  // this mode doesn't rely on SGX capable system, but the results can not be
  // cryptographically authenticated
  uint32_t collateral_expiration_status = 1;
  sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
  quote3_error_t dcap_ret = sgx_qvl_verify_quote(
      pquote, SCAST(uint32_t, quote_size), &collateral_data, current_time,
      &collateral_expiration_status, &quote_verification_result,
      NULL,  // qve_report_info is NULL means qvl mode
      0, NULL);
  if (dcap_ret != SGX_QL_SUCCESS) {
    ELOG_ERROR("Fail to verify dcap quote: 0x%04x\n", dcap_ret);
    return TEE_ERROR_RA_VERIFY_DCAP_QUOTE;
  }

  // check verification result
  switch (quote_verification_result) {
    case SGX_QL_QV_RESULT_OK:
      ELOG_DEBUG("Verify dcap quote successfully");
      break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
      ELOG_WARN("Dcap quote verification with Non-terminal result: 0x%x",
                quote_verification_result);
      break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
      ELOG_ERROR("Fail to verify dcap quote: 0x%x", quote_verification_result);
      return TEE_ERROR_RA_VERIFY_DCAP_QUOTE_RESULT;
  }

  return TEE_SUCCESS;
}
}  // namespace attestation
}  // namespace kubetee
