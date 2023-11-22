#include <string>

#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/instance/trusted_unified_function.h"

#include "utils/untrusted/untrusted_memory.h"

#include "instance/platforms/sgx/untrusted/untrusted_ree_sgx.h"
#include "instance/platforms/sgx/untrusted/untrusted_ree_sgx_ecall.h"

namespace kubetee {
namespace attestation {

TeeErrorCode ReeInstanceSgx::EnclaveIdToTeeIdentity(const sgx_enclave_id_t eid,
                                                    std::string* tee_identity) {
  if (eid == 0) {
    TEE_LOG_ERROR("Zero enclave id");
    return TEE_ERROR_ENCLAVE_NOTINITIALIZED;
  }

  tee_identity->assign(std::to_string(eid));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstanceSgx::TeeIdentityToEnclaveId(
    const std::string& tee_identity, sgx_enclave_id_t* eid) {
  // Empty tee_identity string
  if (tee_identity.empty()) {
    TEE_LOG_ERROR("Empty TEE identity");
    return TEE_ERROR_INVALID_TEE_IDENTITY;
  }

  // Cannot convert tee_identity string to enclave id
  try {
    *eid = std::stoll(tee_identity);
  } catch (const std::exception& e) {
    TEE_LOG_ERROR("Invalid TEE identity");
    return TEE_ERROR_INVALID_TEE_IDENTITY;
  }

  // Invalid converted enclave id
  if (*eid == 0) {
    TEE_LOG_ERROR("Zero enclave id");
    return TEE_ERROR_INVALID_TEE_IDENTITY;
  }

  return TEE_SUCCESS;
}

TeeErrorCode ReeInstanceSgx::Initialize(const UaTeeInitParameters& param,
                                        std::string* tee_identity) {
  // Try to create a enclave instance
  sgx_enclave_id_t eid = 0;
  sgx_status_t rc = sgx_create_enclave(param.trust_application.data(),
                                       SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
  if (rc != SGX_SUCCESS) {
    TEE_LOG_ERROR("Fail to create enclave: 0x%X", rc);
    return TEE_ERROR_CREATE_ENCLAVE;
  }

  TEE_LOG_INFO("Create enclave success: eid = %ld", eid);
  TEE_CHECK_RETURN(EnclaveIdToTeeIdentity(eid, tee_identity));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstanceSgx::Finalize(const std::string& tee_identity) {
  sgx_enclave_id_t eid = 0;
  TEE_CHECK_RETURN(TeeIdentityToEnclaveId(tee_identity, &eid));
  sgx_status_t rc = sgx_destroy_enclave(eid);
  if (rc != SGX_SUCCESS) {
    TEE_LOG_ERROR("Fail to destroy enclave: 0x%X", rc);
    return TEE_ERROR_DESTROY_ENCLAVE_FAILED;
  }
  TEE_LOG_INFO("Destroy enclave success: eid = %ld", eid);
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstanceSgx::TeeRun(const std::string& tee_identity,
                                    const std::string& function_name,
                                    const google::protobuf::Message& request,
                                    google::protobuf::Message* response) {
  // Prepare enclave id
  sgx_enclave_id_t eid = 0;
  TEE_CHECK_RETURN(TeeIdentityToEnclaveId(tee_identity, &eid));
  // Prepare unified function parameters
  std::string params_str;
  kubetee::UnifiedFunctionParams params;
  params.set_tee_identity(tee_identity);
  params.set_function_name(function_name);
  PB2JSON(params, &params_str);
  // Prepare request string
  std::string req_str;
  PB2JSON(request, &req_str);
  // Prepare the temprary response buf
  char* res_buf = 0;
  size_t res_len = 0;
  // Finally call the ecall function
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  sgx_status_t rc =
      ecall_TeeRun(eid, &ret, params_str.data(), params_str.size(),
                   req_str.data(), req_str.size(), &res_buf, &res_len);
  if ((TEE_ERROR_MERGE(ret, rc)) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to do ecall_TeeRun: 0x%x/0x%x", ret, rc);
    return TEE_ERROR_MERGE(ret, rc);
  }
  if (res_buf && (res_len != 0)) {
    std::string res_str(res_buf, res_len);
    UntrustedMemoryFree(&res_buf);
    TEE_LOG_DEBUG("Tee Run response[%ld]: %s", res_len, res_str.c_str());
    JSON2PB(res_str, response);
  } else if (res_len) {
    // The res_buf and res_len may be zero when there is no response data
    // But the res_buf should not be NULL if res_len is not zero.
    TEE_LOG_ERROR("Invalid ecall_TeeRun buffer: %p/%ld", res_buf, res_len);
    return TEE_ERROR_INVALID_ECALL_BUFFER;
  } else {
    TEE_LOG_DEBUG("No response for %s", function_name.c_str());
  }

  return TEE_SUCCESS;
}

TeeErrorCode ReeInstanceSgx::TeePublicKey(const std::string& tee_identity,
                                          std::string* public_key) {
  char buf[kMaxPublicKeyLengh] = {0};
  int len = kMaxPublicKeyLengh;
  TeeErrorCode ret = 0;
  sgx_enclave_id_t eid = 0;
  TEE_CHECK_RETURN(TeeIdentityToEnclaveId(tee_identity, &eid));
  sgx_status_t rc = ecall_UaGetPublicKey(eid, &ret, buf, len, &len);
  if (ret || rc) {
    TEE_LOG_ERROR("Fail to get public key in enclave: 0x%x/0x%x", ret, rc);
    return TEE_ERROR_RA_GET_PUBLIC_KEY;
  }
  public_key->assign(buf, len);
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstanceSgx::SealData(const std::string& tee_identity,
                                      const std::string& plain_str,
                                      std::string* sealed_str,
                                      bool tee_bound) {
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;

  std::string bound_str = tee_bound ? "true" : "false";
  req.add_argv()->assign(plain_str);
  req.add_argv()->assign(bound_str);
  TEE_CHECK_RETURN(TeeRun(tee_identity, "TeeSealData", req, &res));
  if (res.result_size() == 0) {
    TEE_LOG_ERROR("Empty SealData response");
    return TEE_ERROR_SEAL_DATA;
  }
  sealed_str->assign(res.result(0));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstanceSgx::UnsealData(const std::string& tee_identity,
                                        const std::string& sealed_str,
                                        std::string* plain_str) {
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;

  req.add_argv()->assign(sealed_str);
  TEE_CHECK_RETURN(TeeRun(tee_identity, "TeeUnsealData", req, &res));
  if (res.result_size() == 0) {
    TEE_LOG_ERROR("Empty UnsealData response");
    return TEE_ERROR_UNSEAL_DATA;
  }
  plain_str->assign(res.result(0));
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
