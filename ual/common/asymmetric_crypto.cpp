#include <string>

#include "attestation/common/asymmetric_crypto.h"
#include "attestation/common/rsa.h"
#include "attestation/common/sm2.h"

static const char rsa_public_key_header_[] = "-----BEGIN RSA PUBLIC KEY-----";
static const char rsa_private_key_header_[] = "-----BEGIN RSA PRIVATE KEY-----";

namespace kubetee {
namespace common {

TeeErrorCode AsymmetricCrypto::GenerateKeyPair(std::string* public_key,
                                               std::string* private_key,
                                               const bool sm_mode) {
  if (sm_mode) {
    SM2Crypto sm2_crypto;
    return sm2_crypto.GenerateKeyPair(public_key, private_key);
  } else {
    RsaCrypto rsa_crypto;
    return rsa_crypto.GenerateKeyPair(public_key, private_key);
  }
}

TeeErrorCode AsymmetricCrypto::Encrypt(const std::string& public_key,
                                       const std::string& src,
                                       std::string* dst,
                                       const bool sm_mode) {
  if (sm_mode) {
    SM2Crypto sm2_crypto;
    return sm2_crypto.Encrypt(public_key, src, dst);
  } else {
    RsaCrypto rsa_crypto;
    return rsa_crypto.Encrypt(public_key, src, dst);
  }
}

TeeErrorCode AsymmetricCrypto::Decrypt(const std::string& private_key,
                                       const std::string& src,
                                       std::string* dst,
                                       const bool sm_mode) {
  if (sm_mode) {
    SM2Crypto sm2_crypto;
    return sm2_crypto.Decrypt(private_key, src, dst);
  } else {
    RsaCrypto rsa_crypto;
    return rsa_crypto.Decrypt(private_key, src, dst);
  }
}

TeeErrorCode AsymmetricCrypto::Sign(const std::string& private_key,
                                    const std::string& msg,
                                    std::string* sigret,
                                    const bool sm_mode) {
  if (sm_mode) {
    SM2Crypto sm2_crypto;
    return sm2_crypto.Sign(private_key, msg, sigret);
  } else {
    RsaCrypto rsa_crypto;
    return rsa_crypto.Sign(private_key, msg, sigret);
  }
}

TeeErrorCode AsymmetricCrypto::Verify(const std::string& public_key,
                                      const std::string& msg,
                                      const std::string& sigbuf,
                                      const bool sm_mode) {
  if (sm_mode) {
    SM2Crypto sm2_crypto;
    return sm2_crypto.Verify(public_key, msg, sigbuf);
  } else {
    RsaCrypto rsa_crypto;
    return rsa_crypto.Verify(public_key, msg, sigbuf);
  }
}

bool AsymmetricCrypto::isSmMode(const std::string& key_str) {
  // if public key empty use smMode instead
  if (key_str.empty()) {
    return smMode;
  }

  if (key_str.find(rsa_public_key_header_) != std::string::npos ||
      key_str.find(rsa_private_key_header_) != std::string::npos) {
    return false;
  }

  return true;
}

}  // namespace common
}  // namespace kubetee
