#ifndef UAL_INCLUDE_ATTESTATION_COMMON_AES_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_AES_H_

#include <iostream>
#include <string>
#include <vector>

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

using kubetee::SymmetricKeyEncrypted;

namespace kubetee {
namespace common {

class AesGcmCrypto {
 public:
  AesGcmCrypto();  // Generate random key if it's not specified
  explicit AesGcmCrypto(const std::string& key) : key_(key) {}
  explicit AesGcmCrypto(const char* key) : key_(key) {}

  // Encrypt the plain string to cipher in SymmetricKeyEncrypted format
  TeeErrorCode Encrypt(const std::string& plain, SymmetricKeyEncrypted* cipher);
  // Decrypt the cipher in SymmetricKeyEncrypted format to plain string
  TeeErrorCode Decrypt(const SymmetricKeyEncrypted& cipher, std::string* plain);

  std::string GetKey() {
    return key_;
  }

  static size_t get_iv_size() {
    return kIvSize;
  }

  static size_t get_mac_size() {
    return kMacSize;
  }

  static size_t get_key_size() {
    return kKeySize;
  }

 private:
  static const size_t kKeySize = 32;  // AES256
  static const size_t kIvSize = 12;
  static const size_t kMacSize = 16;

  std::string key_;
};

}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_AES_H_
