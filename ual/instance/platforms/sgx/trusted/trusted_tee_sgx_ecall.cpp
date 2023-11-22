#include <string>

#include "./sgx_edger8r.h"
#include "./sgx_utils.h"

#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"
#include "attestation/instance/trusted_tee_instance.h"
#include "attestation/instance/trusted_unified_function.h"

#include "instance/platforms/sgx/trusted/trusted_tee_sgx_ocall.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef UA_TEE_TYPE_HYPERENCLAVE
static size_t GetSharedBufFreeSize() {
  const size_t OCALL_SIZE = 8 * sizeof(size_t);
  size_t free_size = sgx_ocremain_size();
  if (free_size > OCALL_SIZE) {
    return free_size - OCALL_SIZE;
  } else {
    return 0;
  }
}

TeeErrorCode UntrustedReadBuf(const char* ubuf, char* tbuf, size_t count) {
  sgx_status_t oc = SGX_ERROR_UNEXPECTED;
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  size_t batch_size = GetSharedBufFreeSize();
  if (batch_size < MIN_MSBUF_BATCH_SIZE && batch_size < count) {
    ELOG_ERROR("There is no enough ms buffer space");
    return TEE_ERROR_SMALL_BUFFER;
  }

  size_t left = count;
  while (left) {
    size_t size = (left > batch_size) ? batch_size : left;
    size_t offset = count - left;
    ELOG_DEBUG("ocall_UntrustedReadBuf 0x%x/%ld", ubuf + offset, size);
    oc = ocall_UntrustedReadBuf(&ret, ubuf + offset, tbuf + offset, size);
    if ((TEE_ERROR_MERGE(ret, oc)) != TEE_SUCCESS) {
      ELOG_ERROR("Fail to do ocall_UntrustedReadBuf: 0x%x/0x%x", ret, oc);
      return TEE_ERROR_MERGE(ret, oc);
    }
    left -= size;
  }
  return TEE_SUCCESS;
}

TeeErrorCode UntrustedWriteBuf(char* ubuf, const char* tbuf, size_t count) {
  sgx_status_t oc = SGX_ERROR_UNEXPECTED;
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  size_t batch_size = GetSharedBufFreeSize();
  // The required count is less than free size. If
  // the required count is more than free size, and
  // the free size is too small, this means Shared buffer is too busy.
  if (batch_size < MIN_MSBUF_BATCH_SIZE && batch_size < count) {
    ELOG_ERROR("There is no enough ms buffer space");
    return TEE_ERROR_SMALL_BUFFER;
  }

  size_t left = count;
  while (left) {
    size_t size = (left > batch_size) ? batch_size : left;
    size_t offset = count - left;
    ELOG_DEBUG("ocall_UntrustedWriteBuf 0x%x/%ld", ubuf + offset, size);
    oc = ocall_UntrustedWriteBuf(&ret, ubuf + offset, tbuf + offset, size);
    if ((TEE_ERROR_MERGE(ret, oc)) != TEE_SUCCESS) {
      ELOG_ERROR("Fail to do ocall_UntrustedWriteBuf: 0x%x/0x%x", ret, oc);
      return TEE_ERROR_MERGE(ret, oc);
    }
    left -= size;
  }
  return TEE_SUCCESS;
}
#endif

TeeErrorCode ecall_TeeRun(const char* params_buf,
                          size_t params_len,
                          const char* req_buf,
                          size_t req_len,
                          char** res_buf,
                          size_t* res_len) {
  // Check the input parameter and request string
  TEE_CHECK_VALIDBUF(params_buf, params_len);
  TEE_CHECK_VALIDBUF(req_buf, req_len);

  // Set empty response buffer and length before any return statement
  *res_buf = nullptr;
  *res_len = 0;

  // check and register functions firstly if they are not registered
  using kubetee::attestation::TeeUnifiedFunctions;
  TeeUnifiedFunctions& tufm = TeeUnifiedFunctions::Mgr();
  TEE_CHECK_RETURN(tufm.RegisterFunctions());

  // Check the tee_identity in function params
  std::string params_str(params_buf, params_len);
  kubetee::UnifiedFunctionParams params;
  JSON2PB(params_str, &params);
  const std::string& function_name = params.function_name();

  using kubetee::attestation::TeeInstance;
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.SetTeeIdentity(params.tee_identity()));

  // Find the function handler
  UnifiedFunction function = tufm.Functions().Get(function_name);
  if (!function) {
    ELOG_ERROR("Cannot find function: %s", function_name.c_str());
    return TEE_ERROR_UNIFIED_FUNCTION_NOT_FOUND;
  }

  // Execute the protobuf ecall function
  std::string req_str(req_buf, req_len);
  std::string res_str;
  ELOG_DEBUG("Tee Run: %s", function_name.c_str());
  TEE_CATCH_RETURN((*function)(req_str, &res_str));

  // Allocate the untrusted memory to return the response
  // !!! Need to free outside of enclave
  size_t res_size = res_str.size();
  if (res_size > 2) {  // ignore empty json string '{}'
    ELOG_DEBUG("UntrustedMemoryAlloc size: %ld", res_size);
    sgx_status_t sc = SGX_ERROR_UNEXPECTED;
    TeeErrorCode ret = TEE_ERROR_GENERIC;
    sc = ocall_UntrustedMemoryAlloc(&ret, res_size, res_buf);
    if ((TEE_ERROR_MERGE(ret, sc) != TEE_SUCCESS)) {
      ELOG_ERROR("Fail to allocate untrusted memory: len=%ld", res_size);
      return TEE_ERROR_MERGE(ret, sc);
    }
#ifdef UA_TEE_TYPE_HYPERENCLAVE
    // For hyperenclave msbuf mode, cannot read untrusted address directly
    TEE_CHECK_RETURN(UntrustedWriteBuf(*res_buf, res_str.data(), res_size));
#else
    memcpy(*res_buf, res_str.data(), res_size);
#endif
  } else {
    res_size = 0;
  }

  *res_len = res_size;
  return TEE_SUCCESS;
}

TeeErrorCode ecall_UaGetPublicKey(char* public_key_buf,
                                  int max,
                                  int* publc_key_len) {
  TEE_CHECK_VALIDBUF(public_key_buf, max);
  // Generate the UAK public key in enclave
  TEE_CHECK_RETURN(TeeInstanceIsInitialized());
  // check the max length of output buffer to return public key
  const std::string& public_key = UakPublic();
  if (SCAST(size_t, max) <= public_key.size()) {
    ELOG_ERROR("Too small public key buffer");
    *publc_key_len = 0;
    return TEE_ERROR_RA_GET_TARGET_INFO;
  }

  // copy public key data and set the real length
  memset(public_key_buf, 0, max);
  memcpy(public_key_buf, public_key.data(), public_key.size());
  *publc_key_len = public_key.size();
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
