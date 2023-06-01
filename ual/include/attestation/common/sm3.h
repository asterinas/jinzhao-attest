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

#define SM3_MAX_LEN 128

class SM3Crypto {
 public:
  static TeeErrorCode calHash(const std::string& message, std::string* hash);
  static TeeErrorCode calHash(const char* data,
                              size_t len,
                              char* hash,
                              size_t expected_size);
};
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_SM3_H_
