#ifndef UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_INSTANCE_ECALL_H_
#define UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_INSTANCE_ECALL_H_

#include <cstdio>

#include "sgx/sgx_error.h"
#include "sgx/sgx_urts.h"

#include "attestation/common/error.h"
#include "attestation/common/type.h"

/// Copy the ecall functions declarations in xxx_u.h
/// to avoid the dependencies to the edl file name.

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_TeeRun(uint64_t eid,
                          TeeErrorCode* ret,
                          const char* params_buf,
                          size_t params_len,
                          const char* req_buf,
                          size_t req_len,
                          char** res_buf,
                          size_t* res_len) __attribute__((weak));

sgx_status_t ecall_UaGetPublicKey(uint64_t eid,
                                  TeeErrorCode* ret,
                                  char* public_key_buf,
                                  int max,
                                  int* public_key_len) __attribute__((weak));

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_INSTANCE_ECALL_H_
