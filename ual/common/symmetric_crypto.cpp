#include <string>

#include "attestation/common/aes.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/sm3.h"
#include "attestation/common/sm4.h"
#include "attestation/common/symmetric_crypto.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

SymmetricCrypto::SymmetricCrypto(const bool sm_mode) {
  size_t key_size = aes_256_key_size;
  if (sm_mode) {
    key_size = sm4_key_size;
  }

  DataBytes rand_key;
  key_ = rand_key.Randomize(key_size).GetStr();
}

TeeErrorCode SymmetricCrypto::Encrypt(const std::string& plain,
                                      SymmetricKeyEncrypted* cipher,
                                      bool sm_mode) {
  if (sm_mode) {
    SM4CbcCrypto sm4_cbc_crypto(key_);
    return sm4_cbc_crypto.Encrypt(plain, cipher);
  } else {
    AesGcmCrypto aes_gcm_crypto(key_);
    return aes_gcm_crypto.Encrypt(plain, cipher);
  }
}

TeeErrorCode SymmetricCrypto::Decrypt(const SymmetricKeyEncrypted& cipher,
                                      std::string* plain,
                                      bool sm_mode) {
  if (sm_mode) {
    SM4CbcCrypto sm4_cbc_crypto(key_);
    return sm4_cbc_crypto.Decrypt(cipher, plain);
  } else {
    AesGcmCrypto aes_gcm_crypto(key_);
    return aes_gcm_crypto.Decrypt(cipher, plain);
  }
}

}  // namespace common
}  // namespace kubetee
