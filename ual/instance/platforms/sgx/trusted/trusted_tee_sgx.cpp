#include <string>

#include "./sgx_utils.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/instance/trusted_tee_instance.h"

#include "instance/platforms/sgx/trusted/trusted_tee_sgx.h"
#include "instance/platforms/sgx/trusted/trusted_tee_sgx_ocall.h"

namespace kubetee {
namespace attestation {

TeeErrorCode TeeInstanceSgx::GenerateAuthReport(
    UaReportGenerationParameters* param,
    kubetee::UnifiedAttestationAuthReport* auth) {
  int rc = SGX_ERROR_UNEXPECTED;
  TeeErrorCode ret = TEE_SUCCESS;
  const size_t report_len_max = 30720;
  unsigned int report_len = 0;
  std::string auth_report_str(report_len_max, '\0');

  // We must set report data in trusted code
  std::string user_data;
  std::string report_identity = param->others.str_report_identity();
  if (!param->report_hex_nonce.empty() &&
      !param->others.hex_user_data().empty()) {
    TEE_LOG_ERROR("Don't support both nonce and user data for SGX like TEE");
    return TEE_ERROR_RA_HAVE_BOTH_NONCE_AND_USER_DATA;
  } else if (!param->report_hex_nonce.empty()) {
    kubetee::common::DataBytes tmp_nonce(param->report_hex_nonce);
    TEE_CHECK_RETURN(tmp_nonce.FromHexStr().GetError());
    user_data.assign(RCAST(char*, tmp_nonce.data()), tmp_nonce.size());
  } else if (!param->others.hex_user_data().empty()) {
    kubetee::common::DataBytes tmp_user_data(param->others.hex_user_data());
    TEE_CHECK_RETURN(tmp_user_data.FromHexStr().GetError());
    user_data.assign(RCAST(char*, tmp_user_data.data()), tmp_user_data.size());
  }
  if (!user_data.empty()) {
    TEE_CHECK_RETURN(TeeInstanceUpdateReportData(user_data, report_identity));
    param->others.clear_hex_user_data();
    param->report_hex_nonce.clear();
  }
  std::string other_params;
  PB2JSON(param->others, &other_params);
  rc = ocall_UntrustGenerateAuthReport(
      &ret, param->tee_identity.c_str(), param->report_type.c_str(),
      param->report_hex_nonce.c_str(), other_params.c_str(),
      CCAST(char*, auth_report_str.data()), report_len_max, &report_len);
  if ((TEE_ERROR_MERGE(ret, rc) != TEE_SUCCESS)) {
    ELOG_ERROR("Fail to create report from ree env: 0x%x/0x%x", ret, rc);
    ELOG_ERROR("Enclave ID: %s", param->tee_identity.c_str());
    ELOG_ERROR("Report Type: %s", param->report_type.c_str());
    ELOG_ERROR("Report Identity: %s", report_identity.c_str());
    return TEE_ERROR_MERGE(ret, rc);
  }
  auth_report_str.resize(report_len);
  JSON2PB(auth_report_str, auth);
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstanceSgx::ReeRun(
    const kubetee::UnifiedFunctionParams& params,
    const google::protobuf::Message& request,
    google::protobuf::Message* response) {
  std::string params_str;
  PB2JSON(params, &params_str);

  std::string req_str;
  PB2JSON(request, &req_str);

  char* res_buf = 0;
  size_t res_len = 0;
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  sgx_status_t oc = SGX_ERROR_UNEXPECTED;
  oc = ocall_ReeRun(&ret, params_str.data(), params_str.size(), req_str.data(),
                    req_str.size(), &res_buf, &res_len);
  if ((TEE_ERROR_MERGE(ret, oc)) != TEE_SUCCESS) {
    ELOG_ERROR("Fail to do ocall_ReeRun: 0x%x/0x%x", ret, oc);
    return TEE_ERROR_MERGE(ret, oc);
  }
  // The response may be empty
  if (res_buf && res_len) {
#ifdef UA_TEE_TYPE_HYPERENCLAVE
    // For hyperenclave msbuf mode, cannot read untrusted address directly
    std::string res_str(res_len, '\0');
    ret = UntrustedReadBuf(res_buf, CCAST(char*, res_str.data()), res_len);
    if (ret != TEE_SUCCESS) {
      res_str.clear();
    }
#else
    std::string res_str(res_buf, res_len);
#endif
    // Always need to free the untrusted buffer
    oc = ocall_UntrustedMemoryFree(&ret, &res_buf);
    if ((TEE_ERROR_MERGE(ret, oc)) != TEE_SUCCESS) {
      ELOG_ERROR("Fail to do ocall_UntrustedMemoryFree: 0x%x/0x%x", ret, oc);
      return TEE_ERROR_MERGE(ret, oc);
    }
    JSON2PB(res_str, response);
  } else {
    ELOG_DEBUG("There is not response for ReeRun: %s",
               params.function_name().c_str());
  }

  return TEE_SUCCESS;
}

TeeErrorCode TeeInstanceSgx::SealData(const std::string& plain_str,
                                      std::string* sealed_str,
                                      bool tee_bound) {
  if (tee_bound) {
    TEE_CHECK_RETURN(SealEnclaveData(plain_str, sealed_str));
  } else {
    TEE_CHECK_RETURN(SealSignerData(plain_str, sealed_str));
  }
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstanceSgx::UnsealData(const std::string& sealed_str,
                                        std::string* plain_str) {
  TEE_CHECK_EMPTY(sealed_str);

  const sgx_sealed_data_t* psealed =
      RCAST(const sgx_sealed_data_t*, sealed_str.data());
  uint32_t plain_size = sgx_get_encrypt_txt_len(psealed);
  plain_str->resize(plain_size);

  uint8_t* pdata = RCAST(uint8_t*, CCAST(char*, plain_str->data()));
  uint32_t returned_size = plain_size;
  sgx_status_t ret = sgx_unseal_data(psealed, NULL, 0, pdata, &returned_size);
  if ((ret != SGX_SUCCESS) || (plain_size != returned_size)) {
    ELOG_ERROR("Fail to unseal data: 0x%x", ret);
    return TEE_ERROR_CODE(ret);
  }

  return TEE_SUCCESS;
}

TeeErrorCode TeeInstanceSgx::SealSignerData(const std::string& plain_str,
                                            std::string* sealed_str) {
  TEE_CHECK_EMPTY(plain_str);

  // Allocate the sealed buffer
  uint32_t data_size = SCAST(uint32_t, plain_str.size());
  uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
  sealed_str->resize(sealed_size);

  // Seal data
  uint8_t* pdata = RCAST(uint8_t*, CCAST(char*, plain_str.data()));
  uint8_t* psealed = RCAST(uint8_t*, CCAST(char*, sealed_str->data()));
  sgx_status_t ret = sgx_seal_data(0, nullptr, data_size, pdata, sealed_size,
                                   RCAST(sgx_sealed_data_t*, psealed));
  if (ret != SGX_SUCCESS) {
    ELOG_ERROR("Failed to seal data of signer: 0x%x", ret);
    sealed_str->clear();
    return TEE_ERROR_CODE(ret);
  }

  ELOG_DEBUG("SealSignerData, size=%d", sealed_size);
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstanceSgx::SealEnclaveData(const std::string& plain_str,
                                             std::string* sealed_str) {
  TEE_CHECK_EMPTY(plain_str);

  // Allocate the sealed buffer
  uint32_t data_size = SCAST(uint32_t, plain_str.size());
  uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
  sealed_str->resize(sealed_size);

  // Seal data
  uint8_t* pdata = RCAST(uint8_t*, CCAST(char*, plain_str.data()));
  uint8_t* psealed = RCAST(uint8_t*, CCAST(char*, sealed_str->data()));
  sgx_status_t ret = sgx_seal_data_ex(
      SGX_KEYPOLICY_MRENCLAVE, attributes_, misc_select_, 0, nullptr, data_size,
      pdata, sealed_size, RCAST(sgx_sealed_data_t*, psealed));
  if (ret != SGX_SUCCESS) {
    sealed_str->clear();
    ELOG_ERROR("Failed to seal data of enclave: 0x%x", ret);
    return TEE_ERROR_CODE(ret);
  }
  ELOG_DEBUG("SealEnclaveData, size=%d", sealed_size);
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
