#include <string>

#include "attestation/common/attestation.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"
#include "attestation/generation/core/generator_interface.h"

namespace kubetee {
namespace attestation {

/// @brief Prepare SGX like report data
///
/// Case 1: If UAK is initialized, then UAK public is not empty
///   Use the first 32 bytes of report data as the user data.
///   The higher 32 bytes will be filled by public key hash in enclave.
/// Case 2: Just use the user data as binray report data
///
TeeErrorCode AttestationGeneratorInterface::PrepareReportData(
    const UaReportGenerationParameters& param,
    uint8_t* report_data_buf,
    size_t report_data_len) {
  // Here, we check the size of sgx_report_data_t in case SGX SDK changes it
  if (report_data_len != (2 * kSha256Size)) {
    TEE_LOG_ERROR("Unexpected report data size");
    return TEE_ERROR_RA_REPORT_DATA_SIZE;
  }
  if (param.report_hex_nonce.size() > 2 * kSha256Size) {
    TEE_LOG_ERROR("Too long hex nonce string");
    return TEE_ERROR_RA_TOO_LONG_NONCE;
  }
  if (param.others.hex_user_data().size() > 2 * kSha256Size) {
    TEE_LOG_ERROR("Too long hex user data string");
    return TEE_ERROR_RA_TOO_LONG_USER_DATA;
  }
  if (!param.report_hex_nonce.empty() &&
      !param.others.hex_user_data().empty()) {
    TEE_LOG_ERROR("Don't support both nonce and user data");
    return TEE_ERROR_RA_HAVE_BOTH_NONCE_AND_USER_DATA;
  }

  // Report data from nonce or user_data, and public key
  uint8_t report_data[2 * kSha256Size] = {0};
  memset(report_data, 0, 2 * kSha256Size);
  if (!param.report_hex_nonce.empty()) {
    kubetee::common::DataBytes tmp_nonce(param.report_hex_nonce);
    TEE_CHECK_RETURN(tmp_nonce.FromHexStr().GetError());
    tmp_nonce.Export(report_data, tmp_nonce.size());
  }
  if (!param.others.hex_user_data().empty()) {
    kubetee::common::DataBytes tmp_user_data(param.others.hex_user_data());
    TEE_CHECK_RETURN(tmp_user_data.FromHexStr().GetError());
    tmp_user_data.Export(report_data, tmp_user_data.size());
  }
  if (!param.others.pem_public_key().empty()) {
    kubetee::common::DataBytes tmp_pubkey(param.others.pem_public_key());
    TEE_CHECK_RETURN(tmp_pubkey.ToSHA256().GetError());
    tmp_pubkey.Export(report_data + kSha256Size, kSha256Size);
  }

  // Copy the final report_data
  memset(report_data_buf, 0, report_data_len);
  memcpy(report_data_buf, RCAST(char*, report_data), 2 * kSha256Size);
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorInterface::GetAttesterAttr(
    kubetee::UnifiedAttestationAttributes* attr) {
  *attr = attributes_;
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
