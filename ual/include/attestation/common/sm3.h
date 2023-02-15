#ifndef UAL_INCLUDE_ATTESTATION_COMMON_SM3_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_SM3_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "openssl/evp.h"

#include "attestation/common/crypto.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

class SM3Crypto {
 public:
  static TeeErrorCode calHash(const std::string& message, std::string* hash);
};
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_SM3_H_
