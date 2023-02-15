#ifndef UAL_INCLUDE_ATTESTATION_COMMON_ASYMMETRIC_CRYPTO_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_ASYMMETRIC_CRYPTO_H_

#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

#include "attestation/common/crypto.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

class AsymmetricCrypto {
 public:
  static TeeErrorCode GenerateKeyPair(std::string* public_key,
                                      std::string* private_key,
                                      const bool sm_mode = smMode);

  static TeeErrorCode Encrypt(const std::string& public_key,
                              const std::string& src,
                              std::string* dst,
                              const bool sm_mode = smMode);

  static TeeErrorCode Decrypt(const std::string& private_key,
                              const std::string& src,
                              std::string* dst,
                              const bool sm_mode = smMode);

  static TeeErrorCode Sign(const std::string& private_key,
                           const std::string& msg,
                           std::string* sigret,
                           const bool sm_mode = smMode);

  static TeeErrorCode Verify(const std::string& public_key,
                             const std::string& msg,
                             const std::string& sigbuf,
                             const bool sm_mode = smMode);

  static bool isSmMode(const std::string& key_str);
};
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_ASYMMETRIC_CRYPTO_H_
