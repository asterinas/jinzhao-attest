#ifndef UAL_GENERATION_PLATFORMS_SGX_COMMON_UNTRUSTED_UNTRUSTED_SGX_COMMON_H_
#define UAL_GENERATION_PLATFORMS_SGX_COMMON_UNTRUSTED_UNTRUSTED_SGX_COMMON_H_

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

#ifdef __cplusplus
}
#endif

#endif  // UAL_GENERATION_PLATFORMS_SGX_COMMON_UNTRUSTED_UNTRUSTED_SGX_COMMON_H_
