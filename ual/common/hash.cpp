#include <cstdint>
#include <string>

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/hash.h"
#include "attestation/common/log.h"
#include "attestation/common/sha.h"
#include "attestation/common/sm3.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

TeeErrorCode HashCrypto::calHash(const std::string& message,
                                 std::string* hash,
                                 bool sm_mode) {
  if (sm_mode) {
    SM3Crypto sm3_crypto;
    return sm3_crypto.calHash(message, hash);
  } else {
    Sha sha;
    return sha.sha256(message, hash);
  }
}

TeeErrorCode HashCrypto::calHashHex(const std::string& message,
                                    std::string* hash_hex,
                                    bool sm_mode) {
  std::string hash;
  TEE_CHECK_RETURN(calHash(message, &hash, sm_mode));
  DataBytes hash_bytes(hash);
  *hash_hex = hash_bytes.ToHexStr().GetStr();
  return TEE_SUCCESS;
}

}  // namespace common
}  // namespace kubetee
