#ifndef UAL_INCLUDE_ATTESTATION_COMMON_SM2_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_SM2_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "openssl/ec.h"
#include "openssl/evp.h"

#include "attestation/common/crypto.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

class SM2Crypto {
 public:
  static TeeErrorCode GenerateKeyPair(std::string* ec_public_key,
                                      std::string* ec_private_key);

  static TeeErrorCode Encrypt(const std::string& ec_public_key,
                              const std::string& src,
                              std::string* dst);

  static TeeErrorCode Decrypt(const std::string& ec_private_key,
                              const std::string& src,
                              std::string* dst);

  static TeeErrorCode Sign(const std::string& ec_private_key,
                           const std::string& msg,
                           std::string* signature);

  static TeeErrorCode Verify(const std::string& ec_public_key,
                             const std::string& msg,
                             const std::string& signature);

 private:
  static TeeErrorCode GetEvpKeyCtxPtr(bool is_public_key,
                                      const std::string& key,
                                      EVP_PKEY_ptr* evp_key_ptr);
};
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_SM2_H_
