#ifndef UAL_INCLUDE_ATTESTATION_COMMON_SHA_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_SHA_H_

#include <string>

#include "openssl/evp.h"

#include "attestation/common/crypto.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

class Sha {
 public:
  static TeeErrorCode sha256(const std::string& message, std::string* hash);

 private:
  static TeeErrorCode calHash(const std::string& message,
                              const EVP_MD* type,
                              std::string* hash);
};
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_SHA_H_
