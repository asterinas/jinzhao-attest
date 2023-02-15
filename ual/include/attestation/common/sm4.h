#ifndef UAL_INCLUDE_ATTESTATION_COMMON_SM4_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_SM4_H_

#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

#include "openssl/evp.h"

#include "attestation/common/crypto.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

class SM4Crypto {
 public:
  enum class AlgType : int {
    // AES128_ECB,
    // AES128_CBC,
    // AES128_CTR,
    // AES256_GCM,
    SM4_ECB,
    SM4_CBC,
    SM4_OFB,
    SM4_CFB,
    SM4_CTR,
  };

  SM4Crypto(const AlgType alg_type, const std::string& key);

  SM4Crypto(const AlgType alg_type,
            const std::string& key,
            const std::string& iv);

  TeeErrorCode Encrypt(const std::string& src, std::string* dst);

  TeeErrorCode Decrypt(const std::string& src, std::string* dst);

 private:
  bool isAlgEcbMode(AlgType alg_type);

  TeeErrorCode checkParams(const EVP_CIPHER* evp_cipher);

  AlgType alg_type_;

  std::string key_;

  std::string iv_;
};

class SM4CbcCrypto {
 public:
  explicit SM4CbcCrypto(const std::string key) : key_(key) {}

  TeeErrorCode Encrypt(const std::string& plain, SymmetricKeyEncrypted* cipher);

  TeeErrorCode Decrypt(const SymmetricKeyEncrypted& cipher, std::string* plain);

 private:
  std::string key_;

  size_t sm4_cbc_iv_size_ = 16;
};

}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_SM4_H_
