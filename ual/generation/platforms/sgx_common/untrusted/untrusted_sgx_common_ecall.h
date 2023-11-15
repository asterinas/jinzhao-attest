#ifndef UAL_GENERATION_PLATFORMS_SGX_COMMON_UNTRUSTED_UNTRUSTED_SGX_COMMON_ECALL_H_
#define UAL_GENERATION_PLATFORMS_SGX_COMMON_UNTRUSTED_UNTRUSTED_SGX_COMMON_ECALL_H_

#include <string>

#include "sgx/sgx_error.h"
#include "sgx/sgx_report.h"
#include "sgx/sgx_urts.h"

#include "attestation/common/error.h"
#include "attestation/common/type.h"

/// Copy the ecall functions declarations in xxx_u.h
/// to avoid the dependencies to the edl file name.

#ifdef __cplusplus
extern "C" {
#endif

// clang-format off
sgx_status_t ecall_UaGenerateReport(uint64_t eid,
                                    TeeErrorCode* ret,
                                    const char* report_identity,
                                    const char* hex_spid,
                                    sgx_target_info_t* target_info,
                                    sgx_report_data_t* report_data,
                                    sgx_report_t* report) __attribute__((weak));

sgx_status_t ecall_UaVerifyReport(uint64_t eid,
                                  TeeErrorCode* ret,
                                  sgx_target_info_t* target_info,
                                  sgx_report_t* target_report) __attribute__((weak));

// clang-format on

#ifdef __cplusplus
}
#endif

#endif  // UAL_GENERATION_PLATFORMS_SGX_COMMON_UNTRUSTED_UNTRUSTED_SGX_COMMON_ECALL_H_
