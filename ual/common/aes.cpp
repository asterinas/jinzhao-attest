#include <string>

#include "openssl/aes.h"
#include "openssl/evp.h"

#include "attestation/common/aes.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

// Reference here:https://wiki.openssl.org/
// index.php/EVP_Authenticated_Encryption_and_Decryption

AesGcmCrypto::AesGcmCrypto() {
  DataBytes aes_rand_key;
  key_ = aes_rand_key.Randomize(kKeySize).GetStr();
}

TeeErrorCode AesGcmCrypto::Encrypt(const std::string& plain,
                                   SymmetricKeyEncrypted* cipher) {
  if (key_.size() != kKeySize) {
    ELOG_ERROR("Invalid key, length = %ld", key_.size());
    return TEE_ERROR_CRYPTO_AES_KEY_INVALID;
  }

  if (plain.empty()) {
    ELOG_ERROR("Empty plain data for AEC encryption");
    return TEE_ERROR_CRYPTO_AES_EMPTY_PLAIN;
  }

  DataBytes aes_rand_iv;
  // If IV is not specified, generate rand bytes for it.
  if (cipher->iv().empty()) {
    if (aes_rand_iv.Randomize(kIvSize).empty()) {
      ELOG_ERROR("Fail to generate AES IV");
      return TEE_ERROR_CRYPTO_AES_IV_GENERATE;
    }
    cipher->set_iv(aes_rand_iv.GetStr());
  } else if (cipher->iv().size() != kIvSize) {
    ELOG_ERROR("Invalid IV length %ld", cipher->iv().size());
    return TEE_ERROR_CRYPTO_AES_INVALID_IV;
  }

  // Start the AES encryption from here
  EVP_CIPHER_CTX* ctx = NULL;
  TeeErrorCode ret = TEE_ERROR_CRYPTO_AES_ENCRYPT;

  do {
    // Create the context and check
    if (!(ctx = EVP_CIPHER_CTX_new())) {
      ELOG_ERROR("Fail to create AES cipher context");
      ret = TEE_ERROR_CRYPTO_AES_OUT_OF_MEMORY;
      break;
    }

    // Initialize encrypt, key and IV
    const uint8_t* key = RCAST(const uint8_t*, key_.data());
    const uint8_t* iv = RCAST(const uint8_t*, cipher->iv().data());
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
      ELOG_ERROR("Initialise encrypt, key and IV failed.");
      break;
    }

    // Provide AAD data if exist
    int len = 0;
    const uint8_t* aad = RCAST(const uint8_t*, cipher->aad().data());
    const int aad_len = cipher->aad().size();
    if (aad_len && !EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
      ELOG_ERROR("Provide AAD data failed.");
      break;
    }

    // Provide the message to be encrypted, and obtain the encrypted output.
    const uint8_t* src = RCAST(const uint8_t*, plain.data());
    const int src_len = plain.size();
    std::string* aes_cipher = cipher->mutable_cipher();
    aes_cipher->resize(SCAST(size_t, src_len), '\0');
    uint8_t* dst = RCAST(uint8_t*, CCAST(char*, aes_cipher->data()));
    if (!EVP_EncryptUpdate(ctx, dst, &len, src, src_len)) {
      ELOG_ERROR("Fail to obtain the encrypted output.");
      break;
    }
    if (len != src_len) {
      ELOG_ERROR("Unexpected AES encrypt cipher size");
      break;
    }

    // Finalise the encryption. Normally ciphertext bytes may be written at
    // this stage, but this does not occur in GCM mode
    if (!EVP_EncryptFinal_ex(ctx, dst + len, &len)) {
      ELOG_ERROR("Finalise the encryption failed.");
      break;
    }
    if (len != 0) {
      ELOG_ERROR("Unexpected AES_GCM encrypt final length");
      break;
    }

    // Get mac
    std::string* aes_mac = cipher->mutable_mac();
    aes_mac->resize(SCAST(size_t, kMacSize), '\0');
    uint8_t* mac = RCAST(uint8_t*, CCAST(char*, aes_mac->data()));
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kMacSize, mac)) {
      ELOG_ERROR("Fail to get mac");
      break;
    }

    ret = TEE_SUCCESS;
  } while (0);

  // Clean up and return
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
  return ret;
}

TeeErrorCode AesGcmCrypto::Decrypt(const SymmetricKeyEncrypted& cipher,
                                   std::string* plain) {
  // Check all input parameters
  if (key_.size() != kKeySize) {
    ELOG_ERROR("Invalid key, length = %ld", key_.size());
    return TEE_ERROR_CRYPTO_AES_KEY_INVALID;
  }
  if (cipher.cipher().empty()) {
    ELOG_ERROR("Invalid AES decryption cipher data");
    return TEE_ERROR_CRYPTO_AES_EMPTY_CIPHER;
  }
  if (cipher.iv().size() != kIvSize) {
    ELOG_ERROR("Invalid AES decryption IV size: %ld", cipher.iv().size());
    return TEE_ERROR_CRYPTO_AES_INVALID_IV;
  }
  if (cipher.mac().size() != kMacSize) {
    ELOG_ERROR("Invalid AES decryption mac size: %ld", cipher.mac().size());
    return TEE_ERROR_CRYPTO_AES_INVALID_MAC;
  }

  // Begin the openssl AES decryption
  TeeErrorCode ret = TEE_ERROR_CRYPTO_AES_DECRYPT;
  EVP_CIPHER_CTX* ctx = NULL;

  do {
    // Create the context and check it
    if (!(ctx = EVP_CIPHER_CTX_new())) {
      ELOG_ERROR("Fail to create AES cipher context");
      ret = TEE_ERROR_CRYPTO_AES_OUT_OF_MEMORY;
      break;
    }

    // Initialise decrypt, key and IV
    const uint8_t* key = RCAST(uint8_t*, CCAST(char*, key_.data()));
    const uint8_t* iv = RCAST(uint8_t*, CCAST(char*, cipher.iv().data()));
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
      ELOG_ERROR("Initialise decrypt, key and IV failed.");
      break;
    }

    // Provide AAD data if exist
    int len = 0;
    const uint8_t* aad = RCAST(uint8_t*, CCAST(char*, cipher.aad().data()));
    const int aad_len = SCAST(int, cipher.aad().size());
    if (aad_len && !EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
      ELOG_ERROR("Provide AAD data failed.");
      break;
    }

    // Decrypt message, obtain the plain text output
    const uint8_t* src = RCAST(uint8_t*, CCAST(char*, cipher.cipher().data()));
    const int src_len = SCAST(int, cipher.cipher().size());
    plain->resize(src_len, '\0');
    uint8_t* dst = RCAST(uint8_t*, CCAST(char*, plain->data()));
    if (!EVP_DecryptUpdate(ctx, dst, &len, src, src_len)) {
      ELOG_ERROR("Fail to obtain the plain text output");
      break;
    }
    if (len != src_len) {
      ELOG_ERROR("Unexpected AES decrypt plain text size");
      break;
    }

    // Update expected mac value
    uint8_t* mac = RCAST(uint8_t*, CCAST(char*, cipher.mac().data()));
    const int mac_len = SCAST(int, cipher.mac().size());
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, mac_len, mac)) {
      ELOG_ERROR("Update expected mac value failed.");
      break;
    }

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plain text is not trustworthy.
    if (EVP_DecryptFinal_ex(ctx, dst + len, &len) <= 0) {
      ELOG_ERROR("Finalise the decryption failed.");
      break;
    }
    if (len != 0) {
      ELOG_ERROR("Unexpected AES_GCM decrypt final length");
      break;
    }

    ret = TEE_SUCCESS;
  } while (0);

  // Clean up and return
  if (ctx != NULL) {
    EVP_CIPHER_CTX_free(ctx);
  }
  return ret;
}

}  // namespace common
}  // namespace kubetee
