#include <string>
#include <vector>

#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "attestation/common/asymmetric_crypto.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/hash.h"
#include "attestation/common/log.h"
#include "attestation/common/symmetric_crypto.h"
#include "attestation/common/type.h"

#include "attestation/common/envelope.h"

namespace kubetee {
namespace common {

TeeErrorCode DigitalEnvelope::Encrypt(const std::string& public_key,
                                      const std::string& plain,
                                      DigitalEnvelopeEncrypted* envelope) {
  ELOG_DEBUG("Encrypt secret to digital envelope: %s", name_.c_str());
  if (public_key.empty()) {
    ELOG_ERROR("Envelope encrypt public key should not be empty.");
    return TEE_ERROR_CRYPTO_ENVELOPE_ENCRYPT_PUBKEY;
  }
  if (plain.empty()) {
    ELOG_ERROR("Input plain text should not be empty.");
    return TEE_ERROR_CRYPTO_ENVELOPE_ENCRYPT_PLAIN;
  }

  // Get sm_mode by asymmetric key
  AsymmetricCrypto asymmetric_crypto;
  bool sm_mode = asymmetric_crypto.isSmMode(public_key);

  // Set AAD to envelope name if it's not specified
  SymmetricKeyEncrypted* symmetric_cipher = envelope->mutable_aes_cipher();
  if (!name_.empty() && symmetric_cipher->aad().empty()) {
    symmetric_cipher->set_aad(name_);
  }

  // Do Symmetric Encryption
  SymmetricCrypto symmetric_crypto;
  TEE_CHECK_RETURN(symmetric_crypto.Encrypt(plain, symmetric_cipher, sm_mode));

  // Encrypt Symmetric key by Asymmetric public key
  TEE_CHECK_RETURN(
      asymmetric_crypto.Encrypt(public_key, symmetric_crypto.GetKey(),
                                envelope->mutable_encrypted_key()));

  return TEE_SUCCESS;
}

TeeErrorCode DigitalEnvelope::Decrypt(const std::string& private_key,
                                      const DigitalEnvelopeEncrypted& envelope,
                                      std::string* plain) {
  ELOG_DEBUG("Decrypt secret in digital envelope: %s", name_.c_str());
  if (private_key.empty()) {
    ELOG_ERROR("Envelope decrypt private key should not be empty.");
    return TEE_ERROR_CRYPTO_ENVELOPE_DECRYPT_PRIKEY;
  }

  // Get sm_mode by asymmetric key
  AsymmetricCrypto asymmetric_crypto;
  bool sm_mode = asymmetric_crypto.isSmMode(private_key);

  // Decrypt the Symmetric key by Asymmetric private key
  std::string symmetric_key;
  TEE_CHECK_RETURN(asymmetric_crypto.Decrypt(
      private_key, envelope.encrypted_key(), &symmetric_key, sm_mode));

  // Decrypt the secret data with Symmetric key
  SymmetricCrypto symmetric_crypto(symmetric_key);
  TEE_CHECK_RETURN(
      symmetric_crypto.Decrypt(envelope.aes_cipher(), plain, sm_mode));

  return TEE_SUCCESS;
}

TeeErrorCode DigitalEnvelope::Sign(const std::string& private_key,
                                   const std::string& plain,
                                   DigitalEnvelopeEncrypted* envelope) {
  ELOG_DEBUG("Sign the digital envelope: %s", name_.c_str());

  // Get sm_mode by asymmetric key
  AsymmetricCrypto asymmetric_crypto;
  bool sm_mode = asymmetric_crypto.isSmMode(private_key);

  // Set the HASH value
  std::string hash;
  TEE_CHECK_RETURN(HashCrypto::calHashHex(plain, &hash, sm_mode));
  envelope->set_plain_hash(hash);

  // Sign and set the plain HASH value
  TEE_CHECK_RETURN(asymmetric_crypto.Sign(
      private_key, hash, envelope->mutable_plain_hash_sig(), sm_mode));

  return TEE_SUCCESS;
}

TeeErrorCode DigitalEnvelope::Verify(const std::string& public_key,
                                     const std::string& plain,
                                     const DigitalEnvelopeEncrypted& envelope) {
  ELOG_DEBUG("Verify the signature in digital envelope: %s", name_.c_str());

  if (envelope.plain_hash().empty() || envelope.plain_hash_sig().empty()) {
    ELOG_ERROR("Empty hash or signature value");
    return TEE_ERROR_CRYPTO_ENVELOPE_VERIFY_PARAM;
  }

  // Get sm_mode by asymmetric key
  AsymmetricCrypto asymmetric_crypto;
  bool sm_mode = asymmetric_crypto.isSmMode(public_key);

  // Verify the HASH value
  std::string cal_hash;
  TEE_CHECK_RETURN(HashCrypto::calHashHex(plain, &cal_hash, sm_mode));
  if (envelope.plain_hash() != cal_hash) {
    ELOG_ERROR("Fail to compare the hash value");
    ELOG_DEBUG("actual hash: %s", cal_hash.c_str());
    ELOG_DEBUG("expected hash: %s", envelope.plain_hash().c_str());
    return TEE_ERROR_CRYPTO_ENVELOPE_VERIFY_HASH;
  }

  // Verify the signature
  TEE_CHECK_RETURN(asymmetric_crypto.Verify(
      public_key, cal_hash, envelope.plain_hash_sig(), sm_mode));

  return TEE_SUCCESS;
}

TeeErrorCode DigitalEnvelope::EnvelopeEncryptAndSign(
    const std::string& encrypt_pubkey,
    const std::string& signing_prvkey,
    const std::string& plain,
    kubetee::DigitalEnvelopeEncrypted* env) {
  TEE_CHECK_RETURN(Encrypt(encrypt_pubkey, plain, env));
  TEE_CHECK_RETURN(Sign(signing_prvkey, plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode DigitalEnvelope::EnvelopeDecryptAndVerify(
    const std::string& decrypt_prvkey,
    const std::string& verify_pubkey,
    const kubetee::DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  TEE_CHECK_RETURN(Decrypt(decrypt_prvkey, env, plain));
  TEE_CHECK_RETURN(Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

}  // namespace common
}  // namespace kubetee
