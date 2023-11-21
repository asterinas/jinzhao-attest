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
#include "attestation/platforms/csv.h"

#include "verification/platforms/csv/csv_utils.h"
#include "verification/platforms/csv/hygoncert.h"
#include "verification/platforms/csv/verifier_csv.h"

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationVerifierCsv::Initialize(
    const kubetee::UnifiedAttestationReport& report) {
  if (!report.json_nested_reports().empty()) {
    JSON2PB(report.json_nested_reports(), &nested_reports_);
  }
  report_type_ = report.str_report_type();

  // Check the platform
  if (report.str_tee_platform() != kUaPlatformCsv) {
    ELOG_ERROR("It's not %s platfrom, input platform is [%s]", kUaPlatformCsv,
               report.str_tee_platform().c_str());
    return TEE_ERROR_RA_VERIFY_ATTR_TEE_PLATFORM;
  }

  // Get the report data, which is serialized json string
  kubetee::HygonCsvReport hygon_csv_report;
  JSON2PB(report.json_report(), &hygon_csv_report);
  b64_report_ = hygon_csv_report.b64_quote();
  report_.SetValue(b64_report_);
  TEE_CHECK_RETURN(report_.FromBase64().GetError());
  // Get verification collateral
  if (!hygon_csv_report.json_cert_chain().empty()) {
    JSON2PB(hygon_csv_report.json_cert_chain(), &cert_chain_);
  }

  // Parse the attester attributes in CSV report
  TEE_CHECK_RETURN(ParseAttributes());

  // Set the platform for UnifiedAttestationAttributes
  attributes_.set_str_tee_platform(kUaPlatformCsv);

  // Set the hex_spid empty
  attributes_.set_hex_spid("");

  // Show the attester attributes in report
  ELOG_DEBUG("Initialize CSV verifier successfully");
  TEE_CHECK_RETURN(ShowAttesterAttributes());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierCsv::VerifyPlatform(
    const kubetee::UnifiedAttestationAttributes& attr) {
  TEE_UNREFERENCED_PARAMETER(attr);

  // Check the report type if the BackgroundCheck type return unsupport
  if (report_type_ == kUaReportTypeBgcheck) {
    ELOG_ERROR("BackgroundCheck type is not supported to be verified");
    return TEE_ERROR_RA_VERIFY_NEED_RERERENCE_DATA;
  }

  csv_attestation_report* report =
      RCAST(csv_attestation_report*, report_.data());
  TEE_CHECK_RETURN(VerifyCertChain(cert_chain_, report));
  TEE_CHECK_RETURN(VerifyReportSignature(report));
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierCsv::GetReportQuote(std::string* quote) {
  quote->assign(b64_report_);
  return TEE_SUCCESS;
}

/// Parse the following fields in csv_attestation_report struct
///     hash_block_t user_pubkey_digest;
///     uint8_t vm_id[CSV_VM_ID_SIZE];
///     uint8_t vm_version[CSV_VM_VERSION_SIZE];
///     uint8_t user_data[CSV_ATTESTATION_USER_DATA_SIZE];
///     uint8_t mnonce[CSV_ATTESTATION_MNONCE_SIZE];
///     hash_block_t measure;
///     uint32_t policy;
TeeErrorCode AttestationVerifierCsv::ParseAttributes() {
  csv_attestation_report* report =
      RCAST(csv_attestation_report*, report_.data());
  uint32_t anonce = report->anonce;

  kubetee::common::DataBytes vmid(report->vm_id, CSV_VM_ID_SIZE);
  TEE_CHECK_RETURN(RetrieveData(&vmid, anonce));
  attributes_.set_hex_prod_id(vmid.ToHexStr().GetStr());

  kubetee::common::DataBytes vmversion(report->vm_version, CSV_VM_VERSION_SIZE);
  TEE_CHECK_RETURN(RetrieveData(&vmversion, anonce));
  attributes_.set_hex_platform_sw_version(vmversion.ToHexStr().GetStr());

  kubetee::common::DataBytes userdata(report->user_data,
                                      CSV_USED_USER_DATA_SIZE);
  TEE_CHECK_RETURN(RetrieveData(&userdata, anonce));
  attributes_.set_hex_user_data(userdata.ToHexStr().GetStr());

  kubetee::common::DataBytes pubkey(report->user_data + CSV_USED_USER_DATA_SIZE,
                                    HASH_BLOCK_SIZE);
  TEE_CHECK_RETURN(RetrieveData(&pubkey, anonce));
  attributes_.set_hex_hash_or_pem_pubkey(pubkey.ToHexStr().GetStr());

  kubetee::common::DataBytes mnonce(report->mnonce,
                                    CSV_ATTESTATION_MNONCE_SIZE);
  TEE_CHECK_RETURN(RetrieveData(&mnonce, anonce));
  attributes_.set_hex_nonce(mnonce.ToHexStr().GetStr());

  kubetee::common::DataBytes platform_mr(report->measure.block,
                                         HASH_BLOCK_SIZE);
  TEE_CHECK_RETURN(RetrieveData(&platform_mr, anonce));
  attributes_.set_hex_boot_measurement(platform_mr.ToHexStr().GetStr());

  kubetee::common::DataBytes policy(RCAST(uint8_t*, &(report->policy)),
                                    sizeof(uint32_t));
  TEE_CHECK_RETURN(RetrieveData(&policy, anonce));
  attributes_.set_hex_secure_flags(policy.ToHexStr().GetStr());

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierCsv::VerifyCertChain(
    const kubetee::HygonCsvCertChain& cert_chain,
    csv_attestation_report* report) {
  // Check wether there is something dismatched.
  if ((sizeof(hygon_root_cert_t) != HYGON_CERT_SIZE) ||
      (sizeof(csv_cert_t) != HYGON_CSV_CERT_SIZE)) {
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_SIZEOF_CHECK;
  }

  // Get hsk and cek certificate from collateral
  if (cert_chain.b64_hsk_cert().empty() || cert_chain.b64_cek_cert().empty()) {
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_COLLATERAL_EMPTY;
  }
  kubetee::common::DataBytes hsk(cert_chain.b64_hsk_cert());
  kubetee::common::DataBytes cek(cert_chain.b64_cek_cert());
  hygon_root_cert_t* hsk_cert =
      RCAST(hygon_root_cert_t*, hsk.FromBase64().data());
  csv_cert_t* cek_cert = RCAST(csv_cert_t*, cek.FromBase64().data());
  // Get pek certificate from report
  csv_cert_t* pek_cert = RCAST(csv_cert_t*, report->pek_cert);

  // The PEK and ChipId are stored in csv_attestation_report, it's necessary
  // to check whether PEK and ChipId have been tampered with.

  // Retrieve mnonce which is the key of sm3-hmac
  hash_block_t hmac;
  memset((void*)&hmac, 0, sizeof(hash_block_t));
  kubetee::common::DataBytes mnonce(report->mnonce,
                                    CSV_ATTESTATION_MNONCE_SIZE);
  TEE_CHECK_RETURN(RetrieveData(&mnonce, report->anonce));
  if (sm3_hmac((const char*)mnonce.data(), CSV_ATTESTATION_MNONCE_SIZE,
               (const unsigned char*)report +
                   CSV_ATTESTATION_REPORT_HMAC_DATA_OFFSET,
               CSV_ATTESTATION_REPORT_HMAC_DATA_SIZE, (unsigned char*)&hmac,
               sizeof(hash_block_t))) {
    ELOG_ERROR("Fail to compute sm3 hmac");
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_HMAC;
  }
  if (memcmp(&hmac, &report->hmac, sizeof(hash_block_t))) {
    ELOG_ERROR("PEK and ChipId may have been tampered with");
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_HMAC_PEK_CHIPID;
  }
  ELOG_DEBUG("Check PEK and ChipId successfully");

  // Retrieve PEK cert and ChipId
  int pek_chipid_size_32 = (offsetof(csv_attestation_report, reserved1) -
                            offsetof(csv_attestation_report, pek_cert)) /
                           sizeof(uint32_t);
  for (int i = 0; i < pek_chipid_size_32; i++) {
    ((uint32_t*)report->pek_cert)[i] ^= report->anonce;
  }

  // Verify HSK cert with HRK
  if (verify_hsk_cert(hsk_cert) != 1) {
    ELOG_ERROR("Fail to verify HSK cert");
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_HSK_CERT;
  }

  // Verify CEK cert with HSK
  if (verify_cek_cert(hsk_cert, cek_cert) != 1) {
    ELOG_ERROR("Fail to verify CEK cert\n");
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_CEK_CERT;
  }

  // Verigy PEK cert with CEK
  if (verify_pek_cert(cek_cert, pek_cert) != 1) {
    ELOG_ERROR("Fail to verify PEK cert");
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_PEK_CERT;
  }

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierCsv::VerifyReportSignature(
    csv_attestation_report* report) {
  csv_cert_t* pek_cert = RCAST(csv_cert_t*, report->pek_cert);

  if (sm2_verify_attestation_report(pek_cert, report) != 1) {
    ELOG_ERROR("failed to verify csv attestation report\n");
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_PEK_CERT;
  }

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierCsv::RetrieveData(
    kubetee::common::DataBytes* data, uint32_t key) {
  uint32_t* d32 = RCAST(uint32_t*, data->data());
  size_t len = data->size();
  if (len % sizeof(uint32_t)) {
    ELOG_ERROR("Not times of sizeof(uint32_t)");
    return TEE_ERROR_RA_VERIFY_HYGON_CSV_DATA_SIZE;
  }
  size_t len32 = len / sizeof(uint32_t);
  for (size_t i = 0; i < len32; i++) {
    d32[i] ^= key;
  }
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
