#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "./sgx_report.h"
#include "./sgx_trts.h"
#include "./sgx_utils.h"

#include "attestation/common/attestation.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"
#include "attestation/instance/trusted_tee_instance.h"
#include "attestation/verification/ua_verification.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode ecall_UaGenerateReport(const char* report_identity,
                                    const char* hex_spid,
                                    sgx_target_info_t* target_info,
                                    sgx_report_data_t* report_data,
                                    sgx_report_t* report) {
  // Check the size of sgx_report_data_t in case SGX SDK changes it
  if (sizeof(sgx_report_data_t) != (2 * kSha256Size)) {
    TEE_LOG_ERROR("Unexpected report data size");
    return TEE_ERROR_RA_REPORT_DATA_SIZE;
  }

  // Use the trusted report data if it is not empty
  const std::string& ua_report_data =
      TeeInstanceReportData(SAFESTR(report_identity));
  if (!ua_report_data.empty() && (ua_report_data.size() <= (2 * kSha256Size))) {
    // Hex decode the trusted report_data
    kubetee::common::DataBytes hex_report_data(ua_report_data);
    TEE_CHECK_RETURN(hex_report_data.FromHexStr().GetError());
    memset(report_data->d, 0, sizeof(sgx_report_data_t));
    memcpy(report_data->d, hex_report_data.data(), hex_report_data.size());
  }

  // Replace the higher 32 bytes by HASH UAK public key if not specified
  kubetee::common::DataBytes report_data_pubkey(report_data->d + kSha256Size,
                                                kSha256Size);
  std::string empty_pubkey =
      "00000000000000000000000000000000"
      "00000000000000000000000000000000";
  if (report_data_pubkey.ToHexStr().GetStr() == empty_pubkey) {
    const std::string& ua_public_key = UakPublic();
    if (!ua_public_key.empty()) {
      kubetee::common::DataBytes pubkey(ua_public_key);
      pubkey.ToSHA256()
          .Export(report_data->d + kSha256Size, kSha256Size)
          .Void();
    }
  }

  // create the enclave report with target info and report_data
  sgx_status_t sgx_ret = sgx_create_report(target_info, report_data, report);
  if (sgx_ret != SGX_SUCCESS) {
    ELOG_ERROR("sgx_create_reportiled: %d", sgx_ret);
    return TEE_ERROR_MERGE(TEE_ERROR_RA_CREATE_ENCLAVE_REPORT, sgx_ret);
  }

  // save the attester attributes
  kubetee::UnifiedAttestationAttributes attester_attr;
  kubetee::common::DataBytes mrenclave(report->body.mr_enclave.m,
                                       sizeof(sgx_measurement_t));
  kubetee::common::DataBytes mrsigner(report->body.mr_signer.m,
                                      sizeof(sgx_measurement_t));
  // Only save the first 32byte as user data, but not sizeof(sgx_report_data_t)
  kubetee::common::DataBytes user_data(report_data->d, kSha256Size);
  attester_attr.set_hex_ta_measurement(mrenclave.ToHexStr().GetStr());
  attester_attr.set_hex_signer(mrsigner.ToHexStr().GetStr());
  attester_attr.set_hex_prod_id(std::to_string(report->body.isv_prod_id));
  attester_attr.set_str_min_isvsvn(std::to_string(report->body.isv_svn));
  attester_attr.set_hex_user_data(user_data.ToHexStr().GetStr());
  attester_attr.set_hex_spid(SAFESTR(hex_spid));
  if ((report->body.attributes.flags & SGX_FLAGS_DEBUG) == SGX_FLAGS_DEBUG) {
    attester_attr.set_bool_debug_disabled("false");
  } else {
    attester_attr.set_bool_debug_disabled("true");
  }
#ifdef UA_TEE_TYPE_HYPERENCLAVE
  attester_attr.set_str_tee_platform(kUaPlatformHyperEnclave);
#endif
#ifdef UA_TEE_TYPE_SGX2
  attester_attr.set_str_tee_platform(kUaPlatformSgxDcap);
#endif
#ifdef UA_TEE_TYPE_SGX1
  attester_attr.set_str_tee_platform(kUaPlatformSgxEpid);
#endif
  TEE_CHECK_RETURN(TeeInstanceSaveEnclaveInfo(attester_attr, report_identity));

  return TEE_SUCCESS;
}

TeeErrorCode ecall_UaVerifyReport(sgx_target_info_t* target_info,
                                  sgx_report_t* target_report) {
#ifdef TEE_MODE_HW
  if (memcmp(target_info->mr_enclave.m, target_report->body.mr_enclave.m,
             sizeof(sgx_measurement_t)) != 0) {
    ELOG_ERROR("MRENCALVE mismatch when verify the target report");
    return TEE_ERROR_RA_MISMATCH_TARGET_MRENCLAVE;
  }
#else
  TEE_UNREFERENCED_PARAMETER(target_info);
  ELOG_WARN("Ignore QE MRENCLAVE check when it's not HW mode");
#endif
  sgx_status_t sgx_ret = sgx_verify_report(target_report);
  if (sgx_ret != SGX_SUCCESS) {
    ELOG_ERROR("Fail to verify the target report");
    return TEE_ERROR_MERGE(TEE_ERROR_RA_VERIFY_QUOTE_ENCLAVE, sgx_ret);
  }

  ELOG_DEBUG("Success to verify the target report");
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
