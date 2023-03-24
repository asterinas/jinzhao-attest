#ifndef UAL_INCLUDE_ATTESTATION_COMMON_ENVELOPE_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_ENVELOPE_H_

#include <string>
#include <vector>

#include "attestation/common/aes.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/rsa.h"

using kubetee::DigitalEnvelopeEncrypted;

extern const char kDefaultEnvelopeName[];

namespace kubetee {
namespace common {

class DigitalEnvelope {
 public:
  explicit DigitalEnvelope(const std::string& name) : name_(name) {}
  explicit DigitalEnvelope(const char* name) : name_(name) {}
  DigitalEnvelope() : name_(kDefaultEnvelopeName) {}

  // Before decrypt, you need to prepare the plain text and public key
  // AES AAD and IV is optional. The default AAD is envelope name, and
  // the default IV is random number generated when do AES encryption.
  TeeErrorCode Encrypt(const std::string& public_key,
                       const std::string& plain,
                       DigitalEnvelopeEncrypted* envelope);

  // Before decrypt, you need to prepare the cipher envelope and private key
  TeeErrorCode Decrypt(const std::string& private_key,
                       const DigitalEnvelopeEncrypted& envelope,
                       std::string* plain);

  // Optional for add signature into the digital envelope
  TeeErrorCode Sign(const std::string& private_key,
                    const std::string& plain,
                    DigitalEnvelopeEncrypted* envelope);

  // Verify the signature in the digital envelope if it exits
  TeeErrorCode Verify(const std::string& public_key,
                      const std::string& plain,
                      const DigitalEnvelopeEncrypted& envelope);

  TeeErrorCode EnvelopeEncryptAndSign(const std::string& encrypt_pubkey,
                                      const std::string& signing_prvkey,
                                      const std::string& plain,
                                      kubetee::DigitalEnvelopeEncrypted* env);

  TeeErrorCode EnvelopeDecryptAndVerify(
      const std::string& decrypt_prvkey,
      const std::string& verify_pubkey,
      const kubetee::DigitalEnvelopeEncrypted& env,
      std::string* plain);

 private:
  const std::string name_;
};

}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_ENVELOPE_H_
