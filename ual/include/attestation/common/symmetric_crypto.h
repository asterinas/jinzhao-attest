#ifndef UAL_INCLUDE_ATTESTATION_COMMON_SYMMETRIC_CRYPTO_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_SYMMETRIC_CRYPTO_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "openssl/evp.h"

#include "attestation/common/crypto.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

using kubetee::SymmetricKeyEncrypted;

namespace kubetee {
namespace common {

class SymmetricCrypto {
 public:
  explicit SymmetricCrypto(const bool sm_mode = smMode);

  explicit SymmetricCrypto(const std::string& key) : key_(key) {}

  TeeErrorCode Encrypt(const std::string& plain,
                       SymmetricKeyEncrypted* cipher,
                       bool sm_mode = smMode);

  TeeErrorCode Decrypt(const SymmetricKeyEncrypted& cipher,
                       std::string* plain,
                       bool sm_mode = smMode);

  std::string GetKey() {
    return key_;
  }

 private:
  std::string key_;

  size_t aes_256_key_size = 32;

  size_t sm4_key_size = 16;
};
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_SYMMETRIC_CRYPTO_H_
