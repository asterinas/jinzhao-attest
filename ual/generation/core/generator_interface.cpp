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
  // Report data may come from nonce or user_data in generation parameters
  std::string user_data;
  if (!param.report_hex_nonce.empty() &&
      !param.others.hex_user_data().empty()) {
    TEE_LOG_ERROR("Don't support both nonce and user data for SGX like TEE");
    return TEE_ERROR_RA_HAVE_BOTH_NONCE_AND_USER_DATA;
  } else if (!param.report_hex_nonce.empty()) {
    kubetee::common::DataBytes tmp_nonce(param.report_hex_nonce);
    TEE_CHECK_RETURN(tmp_nonce.FromHexStr().GetError());
    user_data.assign(RCAST(char*, tmp_nonce.data()), tmp_nonce.size());
  } else if (!param.others.hex_user_data().empty()) {
    kubetee::common::DataBytes tmp_user_data(param.others.hex_user_data());
    TEE_CHECK_RETURN(tmp_user_data.FromHexStr().GetError());
    user_data.assign(RCAST(char*, tmp_user_data.data()), tmp_user_data.size());
  }

  // Here, we check the size of sgx_report_data_t in case SGX SDK changes it
  if (report_data_len != (2 * kSha256Size)) {
    TEE_LOG_ERROR("Unexpected report data size");
    return TEE_ERROR_RA_REPORT_DATA_SIZE;
  }

  // Assume the user data is binary bytes (maybe hash of some more data)
  if ((user_data.size() > report_data_len) ||
      (user_data.size() > USER_DATA_MAX)) {
    TEE_LOG_ERROR("Too much report data for SGX report");
    return TEE_ERROR_RA_TOO_MUCH_REPORT_DATA;
  }

  // Clear the report data
  memset(report_data_buf, 0, report_data_len);

  // Copy user data directly to the beginning of highest 32 bytes.
  if (user_data.size()) {
    memcpy(report_data_buf, user_data.data(), user_data.size());
  }

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorInterface::GetAttesterAttr(
    kubetee::UnifiedAttestationAttributes* attr) {
  *attr = attributes_;
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
