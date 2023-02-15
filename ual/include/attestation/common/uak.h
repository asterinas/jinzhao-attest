#ifndef UAL_INCLUDE_ATTESTATION_COMMON_UAK_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_UAK_H_

#include <string>

#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/pthread.h"
#include "attestation/common/type.h"

using kubetee::AsymmetricKeyPair;

namespace kubetee {
namespace attestation {

class UaIdentityKey {
 public:
  static UaIdentityKey& GetInstance() {
    static UaIdentityKey instance_;

    UA_MUTEX_LOCK(&uak_lock_);
    instance_.Initialize();
    UA_MUTEX_UNLOCK(&uak_lock_);

    return instance_;
  }

  const AsymmetricKeyPair& Uak() {
    return uak_;
  }

  TeeErrorCode UpdateUak(const std::string& private_key,
                         const std::string& public_key);

 private:
  // Hide construction functions
  UaIdentityKey() {}
  UaIdentityKey(const UaIdentityKey&);
  void operator=(UaIdentityKey const&);

  void Initialize();

  // UAK (Unified Attestation Key) for enclave identity
  // Must protect the private key and don't leak it to untrusted world
  AsymmetricKeyPair uak_;

  // mutex for multi-thread protection
  static UA_MUTEX_T uak_lock_;
};

}  // namespace attestation
}  // namespace kubetee

#ifdef __cplusplus
extern "C" {
#endif
///=============
/// C++ API
///=============

/// @brief Set or replace the UAK
extern TeeErrorCode UakUpdate(const std::string& private_key,
                              const std::string& public_key);

/// @brief Get the unified attestation identity RSA key pair
extern const AsymmetricKeyPair& Uak();

/// @brief Get private key of the unified attestation identity RSA key pair
extern const std::string& UakPrivate();

/// @brief Get public key of the unified attestation identity RSA key pair
extern const std::string& UakPublic();

///=============
/// C API
///=============
/// @brief C API for setting the UAK (enclave identity key pair)
/// @param private_key_str: the C type char string of the private key
/// @param public_key_str: the C type char string of the public key
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationUpdateUak(const char* private_key_str,
                                       const char* publick_key_str);

/// @brief C API for geting the UAK priviate key
/// @param private_key_buf: the buffer to get the private key
/// @param private_key_len: Input as max buf len, and output as real len
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationUakPrivate(char* private_key_buf,
                                        int* private_key_len);

/// @brief C API for geting the UAK public key
/// @param public_key_buf: the buffer to get the public key
/// @param public_key_len: Input as max buf len, and output as real len
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationUakPublic(char* public_key_buf,
                                       int* public_key_len);

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_UAK_H_
