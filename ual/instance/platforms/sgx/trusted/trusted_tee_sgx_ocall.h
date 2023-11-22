#ifndef UAL_INSTANCE_PLATFORMS_SGX_TRUSTED_TRUSTED_TEE_SGX_OCALL_H_
#define UAL_INSTANCE_PLATFORMS_SGX_TRUSTED_TRUSTED_TEE_SGX_OCALL_H_

#include <cstdio>

#include "sgx/sgx_report.h"
#include "sgx/sgx_trts.h"
#include "sgx/sgx_utils.h"

#include "attestation/common/type.h"

/// Copy the ocall functions declarations in xxx_t.h
/// to avoid the dependencies to the edl file name.

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ocall_UntrustedMemoryAlloc(TeeErrorCode* ret,
                                        size_t size,
                                        char** buf);

sgx_status_t ocall_UntrustedMemoryFree(TeeErrorCode* ret, char** buf);

sgx_status_t ocall_UntrustedReadBuf(TeeErrorCode* ret,
                                    const char* ubuf,
                                    char* tbuf,
                                    size_t count);

sgx_status_t ocall_UntrustedWriteBuf(TeeErrorCode* ret,
                                     char* ubuf,
                                     const char* tbuf,
                                     size_t count);

sgx_status_t ocall_ReeRun(TeeErrorCode* ret,
                          const char* params_buf,
                          size_t params_len,
                          const char* req_buf,
                          size_t req_len,
                          char** res_buf,
                          size_t* res_len);

sgx_status_t ocall_UntrustGenerateAuthReport(TeeErrorCode* retval,
                                             const char* tee_identity,
                                             const char* report_type,
                                             const char* report_hex_nonce,
                                             const char* report_params,
                                             char* auth_report_buf,
                                             int auth_report_buf_size,
                                             unsigned int* auth_report_len);

#ifdef UA_TEE_TYPE_HYPERENCLAVE
// Minimal size when read or write shared buffer in batch
constexpr size_t MIN_MSBUF_BATCH_SIZE = 1024;

TeeErrorCode UntrustedReadBuf(const char* ubuf, char* tbuf, size_t count);
TeeErrorCode UntrustedWriteBuf(char* ubuf, const char* tbuf, size_t count);
#endif

#ifdef __cplusplus
}
#endif

#endif  // UAL_INSTANCE_PLATFORMS_SGX_TRUSTED_TRUSTED_TEE_SGX_OCALL_H_
