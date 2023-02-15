#ifndef UAL_INCLUDE_ATTESTATION_COMMON_RSA_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_RSA_H_

#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"

#include "attestation/common/crypto.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

constexpr bool kIsPkcs8 = true;
constexpr bool kIsPkcs1 = false;
constexpr bool kIsPublicKey = true;
constexpr bool kIsPrivateKey = false;
constexpr char kRsaKeypairSeparator[] = "-----BEGIN RSA PRIVATE KEY-----";
constexpr char kRsaPubKeyEnd[] = "-----END RSA PUBLIC KEY-----";

constexpr uint64_t kMaxPublicKeyLengh = 4096;

namespace kubetee {
namespace common {

class RsaCrypto {
 public:
  RsaCrypto() {
    bits_ = kRSAKeySizeDefault;
    is_pkcs8_ = false;
  }
  RsaCrypto(int bits) {
    // If bits is 0, use default
    bits_ = bits ? bits : kRSAKeySizeDefault;
    is_pkcs8_ = false;
  }
  RsaCrypto(int bits, bool is_pkcs8) {
    bits_ = bits ? bits : kRSAKeySizeDefault;
    is_pkcs8_ = is_pkcs8;
  }

  /// @brief Generate RSA key pair
  ///
  /// Generate public key and private key in PEM format.
  ///
  /// @param public_key
  /// @param private_key
  ///
  /// @return TEE_SUCCESS on success
  TeeErrorCode GenerateKeyPair(std::string* public_key,
                               std::string* private_key);

  /// @brief Generate RSA key pair
  ///
  /// Generate public key and private key in PEM format.
  ///
  /// @param public_key
  /// @param private_key
  /// @param bit_length, the bit length of key
  /// @param is_pkcs8, true to get pkcs8 type pem key
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Generate(std::string* public_key,
                               std::string* private_key,
                               int bit_length,
                               bool is_pkcs8 = false);

  /// @brief Encrypt
  ///
  /// @param public_key
  /// @param src
  /// @param dst, dst.length() will be the multiples of bits length.
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Encrypt(const std::string& public_key,
                              const std::string& src,
                              std::string* dst);

  /// @brief Decrypt
  ///
  /// @param private_key
  /// @param src, src.length() should be the multiples of bits length
  /// @param dst
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Decrypt(const std::string& private_key,
                              const std::string& src,
                              std::string* dst);

  /// @brief Sign
  ///
  /// @param private_key
  /// @param msg, the input message to be signed
  /// @param sigret, return the signature.
  /// @parem digest_type
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Sign(const std::string& private_key,
                           const std::string& msg,
                           std::string* sigret);

  /// @brief Verify
  ///
  /// @param public_key
  /// @param msg, the input message to be signed
  /// @param sigbuf, signature data
  /// @param digest_type
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Verify(const std::string& public_key,
                             const std::string& msg,
                             const std::string& sigbuf);

  /// @brief get_pem_public_key_size
  ///
  /// @param void
  ///
  /// @return the max size of buffer which is used to save pem type public key.
  static size_t get_pem_public_key_size() {
    return kPubKeyPemSize;
  }

 private:
  // Inside enclave, With every doubling of the RSA key length,
  // decryption is 6-7 times times slower
  static const int kRSAKeySizeDefault = 2048;
  static const int kRSAPaddingSize = 41;
  static const int kRSAPaddingScheme = RSA_PKCS1_OAEP_PADDING;
  static const size_t kPubKeyPemSize = 4096;

  // OpenSSL Error string buffer size
  // ERR_error_string() generates a human-readable string
  // representing the error code e, and places it at buf.
  // buf must be at least 120 bytes long.
  // https://www.openssl.org/docs/man1.0.2/man3/ERR_error_string.html */
  static const int kErrorBufferLength = 128;

  /// @brief Get pem key from RSA key
  ///
  /// @param is_public_key,  true for public key and false for private key
  /// @param key, output the pem key string
  /// @param rsa_ptr, input RSA key
  /// @param is_pkcs8, true to get pkcs8 type pem key
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode GetKeyFromRSA(bool is_public_key,
                                    std::string* key,
                                    const RSA_ptr& rsa_ptr,
                                    bool is_pkcs8 = false);

  /// @brief Get RSA key from pem key
  ///
  /// @param is_public_key,  true for public key and false for private key
  /// @param key, input pem key string
  /// @param rsa_ptr, output the RSA key
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode GetRSAFromKey(bool is_public_key,
                                    const std::string& key,
                                    RSA_ptr* rsa_ptr);

  int bits_ = kRSAKeySizeDefault;
  bool is_pkcs8_ = false;
};

}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_RSA_H_
