#include <stdint.h>
#include <string>

#include "openssl/bio.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/pem.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/sm4.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

SM4Crypto::SM4Crypto(const SM4Crypto::AlgType alg_type,
                     const std::string& key) {
  alg_type_ = alg_type;
  key_ = key;
}

SM4Crypto::SM4Crypto(const SM4Crypto::AlgType alg_type,
                     const std::string& key,
                     const std::string& iv) {
  iv_ = iv;
  alg_type_ = alg_type;
  key_ = key;
}

const EVP_CIPHER* CreateEvpCipher(SM4Crypto::AlgType alg_type) {
  switch (alg_type) {
    case SM4Crypto::AlgType::SM4_ECB:
      return EVP_sm4_ecb();
    case SM4Crypto::AlgType::SM4_CBC:
      return EVP_sm4_cbc();
    case SM4Crypto::AlgType::SM4_OFB:
      return EVP_sm4_ofb();
    case SM4Crypto::AlgType::SM4_CFB:
      return EVP_sm4_cfb();
    case SM4Crypto::AlgType::SM4_CTR:
      return EVP_sm4_ctr();
    default:
      ELOG_ERROR("alg_type is not support");
      return nullptr;
  }
}

TeeErrorCode SM4Crypto::Encrypt(const std::string& src, std::string* dst) {
  const EVP_CIPHER* evp_cipher = CreateEvpCipher(alg_type_);
  if (evp_cipher == nullptr) {
    ELOG_ERROR("CreateEvpCipher by alg_type_ Error");
    return TEE_ERROR_CRYPTO_SM4_EVP_CIPHER;
  }
  TEE_CHECK_RETURN(checkParams(evp_cipher));

  int block_size = 16;
  EVP_CIPHER_CTX_ptr enc_ctx_ptr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (enc_ctx_ptr.get() == nullptr) {
    ELOG_ERROR("EVP_CIPHER_CTX_new enc_ctx Error");
    return TEE_ERROR_CRYPTO_SM4_EVP_CIPHER_CTX;
  }
  int ret = TEE_ERROR_GENERIC;
  if (isAlgEcbMode(alg_type_)) {
    ret = EVP_EncryptInit_ex(enc_ctx_ptr.get(), evp_cipher, nullptr,
                             (const unsigned char*)key_.c_str(), nullptr);
  } else {
    ret = EVP_EncryptInit_ex(enc_ctx_ptr.get(), evp_cipher, nullptr,
                             (const unsigned char*)key_.c_str(),
                             (const unsigned char*)iv_.c_str());
  }
  if (ret != evp_success) {
    ELOG_ERROR("EVP_EncryptInit_ex Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM4_CRYPT_INIT;
  }

  int max_cipher_len = src.length() + block_size;
  unsigned char cipher[max_cipher_len] = {0};

  ret = EVP_EncryptUpdate(enc_ctx_ptr.get(), cipher, &max_cipher_len,
                          (unsigned char*)src.c_str(), src.length());
  ELOG_DEBUG("ret = %d, max_cipher_len = %d", ret, max_cipher_len);
  if (ret != evp_success) {
    ELOG_ERROR("EVP_EncryptUpdate Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM4_CRYPT_UPDATE;
  }

  int final_block_len = 0;
  ret = EVP_EncryptFinal_ex(enc_ctx_ptr.get(), cipher + max_cipher_len,
                            &final_block_len);
  ELOG_DEBUG("ret = %d, max_cipher_len = %d", ret, max_cipher_len);
  if (ret != evp_success) {
    ELOG_ERROR("EVP_EncryptFinal_ex Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM4_CRYPT_FINAL;
  }

  std::string cipher_str((const char*)cipher, max_cipher_len + final_block_len);
  dst->assign(cipher_str);
  return TEE_SUCCESS;
}

TeeErrorCode SM4Crypto::Decrypt(const std::string& src, std::string* dst) {
  const EVP_CIPHER* evp_cipher = CreateEvpCipher(alg_type_);
  if (evp_cipher == nullptr) {
    ELOG_ERROR("CreateEvpCipher by alg_type_ Error");
    return TEE_ERROR_CRYPTO_SM4_EVP_CIPHER;
  }
  TEE_CHECK_RETURN(checkParams(evp_cipher));

  EVP_CIPHER_CTX_ptr dec_ctx_ptr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (dec_ctx_ptr.get() == nullptr) {
    ELOG_ERROR("EVP_CIPHER_CTX_new dec_ctx Error");
    return TEE_ERROR_CRYPTO_SM4_EVP_CIPHER_CTX;
  }

  int ret = TEE_ERROR_GENERIC;
  if (isAlgEcbMode(alg_type_)) {
    ret = EVP_DecryptInit_ex(dec_ctx_ptr.get(), evp_cipher, nullptr,
                             (const unsigned char*)key_.c_str(), nullptr);
  } else {
    ret = EVP_DecryptInit_ex(dec_ctx_ptr.get(), evp_cipher, nullptr,
                             (const unsigned char*)key_.c_str(),
                             (const unsigned char*)iv_.c_str());
  }
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DecryptInit_ex Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM4_CRYPT_INIT;
  }
  int max_plain_len = src.length();
  unsigned char plain[max_plain_len] = {0};

  ret = EVP_DecryptUpdate(dec_ctx_ptr.get(), plain, &max_plain_len,
                          (unsigned char*)src.c_str(), src.length());
  ELOG_DEBUG("ret = %d, max_plain_len = %d", ret, max_plain_len);
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DecryptUpdate Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM4_CRYPT_UPDATE;
  }

  int final_block_len = 0;
  ret = EVP_DecryptFinal_ex(dec_ctx_ptr.get(), plain + max_plain_len,
                            &final_block_len);
  ELOG_DEBUG("ret = %d, final_block_len = %d", ret, final_block_len);
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DecryptFinal_ex Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM4_CRYPT_FINAL;
  }
  std::string plain_str((const char*)plain, max_plain_len + final_block_len);
  dst->assign(plain_str);
  return TEE_SUCCESS;
}

TeeErrorCode SM4CbcCrypto::Encrypt(const std::string& plain,
                                   SymmetricKeyEncrypted* cipher) {
  DataBytes sm4_rand_iv;
  std::string iv = sm4_rand_iv.Randomize(sm4_cbc_iv_size_).GetStr();
  cipher->set_iv(iv);
  SM4Crypto sm4_crypto(SM4Crypto::AlgType::SM4_CBC, key_, iv);
  std::string dst;
  TEE_CHECK_RETURN(sm4_crypto.Encrypt(plain, &dst));
  cipher->set_cipher(dst);
  return TEE_SUCCESS;
}

TeeErrorCode SM4CbcCrypto::Decrypt(const SymmetricKeyEncrypted& cipher,
                                   std::string* plain) {
  if (cipher.iv().empty()) {
    ELOG_ERROR("this alg needs iv information, input iv is empty");
    return TEE_ERROR_CRYPTO_SM4_CHECK_IV;
  }
  SM4Crypto sm4_crypto(SM4Crypto::AlgType::SM4_CBC, key_, cipher.iv());
  return sm4_crypto.Decrypt(cipher.cipher(), plain);
}

TeeErrorCode SM4Crypto::checkParams(const EVP_CIPHER* evp_cipher) {
  // check key length
  size_t key_length = EVP_CIPHER_key_length(evp_cipher);
  if (key_length != key_.length()) {
    ELOG_ERROR("expect key length is %ld, actual key length is %ld", key_length,
               key_.length());
    return TEE_ERROR_CRYPTO_SM4_CHECK_KEY;
  }

  // check iv length
  if (!isAlgEcbMode(alg_type_)) {
    size_t iv_length = EVP_CIPHER_iv_length(evp_cipher);
    if (iv_length != iv_.length()) {
      ELOG_ERROR("expect iv length is %ld, actual iv length is %ld", iv_length,
                 iv_.length());
      return TEE_ERROR_CRYPTO_SM4_CHECK_IV;
    }
  }

  return TEE_SUCCESS;
}

bool SM4Crypto::isAlgEcbMode(SM4Crypto::AlgType alg_type) {
  if (alg_type == SM4Crypto::AlgType::SM4_ECB) {
    return true;
  }

  return false;
}

}  // namespace common
}  // namespace kubetee
