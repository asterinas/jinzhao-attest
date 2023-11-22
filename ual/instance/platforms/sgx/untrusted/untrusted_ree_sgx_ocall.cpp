#include <string>

#include "attestation/common/attestation.h"
#include "attestation/common/protobuf.h"
#include "attestation/instance/untrusted_unified_function.h"

// For ocall_UntrustGenerateAuthReport
#include "attestation/generation/ua_generation.h"

#include "utils/untrusted/untrusted_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode ocall_UntrustedMemoryAlloc(size_t size, char** buf) {
  return UntrustedMemoryAlloc(size, buf);
}

TeeErrorCode ocall_UntrustedMemoryFree(char** buf) {
  UntrustedMemoryFree(buf);
  return TEE_SUCCESS;
}

TeeErrorCode ocall_UntrustedReadBuf(const char* ubuf,
                                    char* tbuf,
                                    size_t count) {
  if (ubuf == NULL || tbuf == NULL || count == 0) {
    return TEE_ERROR_PARAMETERS;
  }
  // malloc() untrusted buffer -> ms buffer -> trusted buffer
  TEE_LOG_DEBUG("ocall_UntrustedReadBuf 0x%x/0x%x/%ld", ubuf, tbuf, count);
  memcpy((unsigned char*)tbuf, (unsigned char*)ubuf, count);
  return TEE_SUCCESS;
}

TeeErrorCode ocall_UntrustedWriteBuf(char* ubuf,
                                     const char* tbuf,
                                     size_t count) {
  if (ubuf == NULL || tbuf == NULL || count == 0) {
    return TEE_ERROR_PARAMETERS;
  }
  // trusted buffer -> ms buffer -> malloc() untrusted buffer
  TEE_LOG_DEBUG("ocall_UntrustedWriteBuf 0x%x/0x%x/%ld", ubuf, tbuf, count);
  memcpy((unsigned char*)ubuf, (unsigned char*)tbuf, count);
  return TEE_SUCCESS;
}

TeeErrorCode ocall_ReeRun(const char* params_buf,
                          size_t params_len,
                          const char* req_buf,
                          size_t req_len,
                          char** res_buf,
                          size_t* res_len) {
  TEE_CHECK_VALIDBUF(params_buf, params_len);
  TEE_CHECK_VALIDBUF(req_buf, req_len);

  // Initialize the return buffer to empty before any return
  *res_buf = 0;
  *res_len = 0;

  // When the first time to call ReeRun
  // register all untrusted unified functions
  using kubetee::attestation::ReeUnifiedFunctions;
  ReeUnifiedFunctions& rufm = ReeUnifiedFunctions::Mgr();
  TEE_CHECK_RETURN(rufm.RegisterFunctions());

  // Get the function name
  std::string params_str(params_buf, params_len);
  kubetee::UnifiedFunctionParams params;
  JSON2PB(params_str, &params);
  UnifiedFunction function = rufm.Functions().Get(params.function_name());
  if (!function) {
    ELOG_ERROR("Cannot find function: %s", params.function_name().c_str());
    return TEE_ERROR_UNIFIED_FUNCTION_NOT_FOUND;
  }

  // Execute the untrusted function
  std::string req_str(req_buf, req_len);
  std::string res_str;
  TEE_CATCH_RETURN((*function)(req_str, &res_str));

  // Set the return buffer if the response is not empty
  if (res_str.size()) {
    TEE_CHECK_RETURN(UntrustedMemoryAlloc(res_str.size(), res_buf));
    memcpy(*res_buf, res_str.data(), res_str.size());
    *res_len = res_str.size();
  }

  TEE_LOG_DEBUG("ReeRun, response addr/len=%p/%ld", *res_buf, *res_len);
  return TEE_SUCCESS;
}

TeeErrorCode ocall_UntrustGenerateAuthReport(const char* tee_identity,
                                             const char* report_type,
                                             const char* report_hex_nonce,
                                             const char* report_params,
                                             char* auth_report_buf,
                                             unsigned int auth_report_buf_size,
                                             unsigned int* auth_report_len) {
  UaReportGenerationParameters param;
  param.tee_identity = SAFESTR(tee_identity);
  param.report_type = SAFESTR(report_type);
  param.report_hex_nonce = SAFESTR(report_hex_nonce);
  JSON2PB(report_params, &param.others);
  std::string auth_report_json;
  TEE_CHECK_RETURN(UaGenerateAuthReportJson(&param, &auth_report_json));
  if (SCAST(size_t, auth_report_buf_size) <= auth_report_json.size()) {
    TEE_LOG_ERROR("Too small auth report buf: %d, report_size: %ld\n",
                  auth_report_buf_size, auth_report_json.size());
    return TEE_ERROR_RA_SMALLER_REPORT_BUFFER;
  }

  *auth_report_len = auth_report_json.size();
  memcpy(auth_report_buf, auth_report_json.data(), *auth_report_len);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
