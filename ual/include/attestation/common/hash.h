#ifndef UAL_INCLUDE_ATTESTATION_COMMON_HASH_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_HASH_H_

#include <string>

#include "openssl/evp.h"

#include "attestation/common/crypto.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

class HashCrypto {
 public:
  static TeeErrorCode calHash(const std::string& message,
                              std::string* hash,
                              bool sm_mode);

  static TeeErrorCode calHashHex(const std::string& message,
                                 std::string* hash_hex,
                                 bool sm_mode);
};
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_HASH_H_
