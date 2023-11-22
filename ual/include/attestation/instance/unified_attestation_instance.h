#ifndef UAL_INCLUDE_ATTESTATION_INSTANCE_UNIFIED_ATTESTATION_INSTANCE_H_
#define UAL_INCLUDE_ATTESTATION_INSTANCE_UNIFIED_ATTESTATION_INSTANCE_H_

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief C API for sealing data
/// @param tee_identity: The identity of TEE or TA instance
///                      In OCCLUM environment, set it to NULL
/// @param plain_buf: Plain string buffer which is to be sealed
/// @param plain_size: Plain string buffer size
/// @param sealed_buf: Output sealed string buffer
/// @param sealed_size: Input for max size and output for real size
/// @param tee_bound: Using seal key bound to tee instance or not
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationSealData(const char* tee_identity,
                                      const char* plain_buf,
                                      const unsigned int plain_size,
                                      char* sealed_buf,
                                      unsigned int* sealed_size,
                                      bool tee_bound);

/// @brief C API for unsealing data
/// @param tee_identity: The identity of TEE or TA instance
///                      In OCCLUM environment, set it to NULL
/// @param sealed_buf: Sealed string buffer which is to be unsealed
/// @param sealed_size: Sealed string buffer size
/// @param plain_buf: Output plain string buffer
/// @param plain_size: Input for max size and output for real size
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationUnsealData(const char* tee_identity,
                                        const char* sealed_buf,
                                        const unsigned int sealed_size,
                                        char* plain_buf,
                                        unsigned int* plain_size);

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_UNIFIED_ATTESTATION_INSTANCE_H_
