#include <stdint.h>
#include <string>

#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/rsa.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

TeeErrorCode RsaCrypto::GetKeyFromRSA(bool is_public_key,
                                      std::string* key,
                                      const RSA_ptr& rsa_ptr,
                                      bool is_pkcs8) {
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free_all);
  if (!bio) {
    ELOG_ERROR("Failed to new BIO");
    return TEE_ERROR_CRYPTO_RSA_GET_KEY_FROM_RSA;
  }

  int ret = 0;
  if (is_pkcs8) {
    EVP_PKEY_ptr pkey(EVP_PKEY_new(), EVP_PKEY_free);
    if (pkey.get()) {
      // EVP_PKEY_free will call RSA_free, so must add reference here
      RSA_up_ref(rsa_ptr.get());
      EVP_PKEY_assign_RSA(pkey.get(), rsa_ptr.get());
    }
    if (is_public_key) {
      ret = PEM_write_bio_PUBKEY(bio.get(), pkey.get());
    } else {
      ret = PEM_write_bio_PrivateKey(bio.get(), pkey.get(), NULL, NULL, 0, NULL,
                                     NULL);
    }
  } else {
    if (is_public_key) {
      ret = PEM_write_bio_RSAPublicKey(bio.get(), rsa_ptr.get());
    } else {
      ret = PEM_write_bio_RSAPrivateKey(bio.get(), rsa_ptr.get(), NULL, NULL, 0,
                                        NULL, NULL);
    }
  }

  if (!ret) {
    ELOG_ERROR("Failed to write bio RSA Key");
    return TEE_ERROR_CRYPTO_RSA_GET_KEY_FROM_RSA;
  }

  int keylen = BIO_pending(bio.get());
  DataBytes pem_str(keylen);
  if (!BIO_read(bio.get(), pem_str.data(), keylen)) {
    ELOG_ERROR("Failed to read BIO");
    return TEE_ERROR_CRYPTO_RSA_GET_KEY_FROM_RSA;
  }
  key->assign(RCAST(char*, pem_str.data()), keylen);
  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::GetRSAFromKey(const bool is_public_key,
                                      const std::string& key,
                                      RSA_ptr* rsa_ptr) {
  void* pkey = RCAST(void*, CCAST(char*, key.c_str()));
  BIO_ptr bio(BIO_new_mem_buf(pkey, -1), BIO_free_all);
  if (!bio) {
    ELOG_ERROR("Failed to new BIO memory buffer");
    return TEE_ERROR_CRYPTO_RSA_GET_RSA_FROM_KEY;
  }

  // Check the pem key type
  RSA* rsa = NULL;
  bool is_pkcs8 = false;
  if ((key.find(PEM_STRING_RSA) == std::string::npos) &&
      (key.find(PEM_STRING_RSA_PUBLIC) == std::string::npos)) {
    is_pkcs8 = true;
  }
  if (is_pkcs8) {
    EVP_PKEY* evp_pkey = NULL;
    if (is_public_key) {
      evp_pkey = PEM_read_bio_PUBKEY(bio.get(), NULL, NULL, NULL);
    } else {
      evp_pkey = PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL);
    }
    if (!evp_pkey) {
      return TEE_ERROR_CRYPTO_RSA_GET_RSA_FROM_KEY;
    } else {
      rsa = EVP_PKEY_get1_RSA(evp_pkey);
      EVP_PKEY_free(evp_pkey);
    }
  } else {
    if (is_public_key) {
      rsa = PEM_read_bio_RSAPublicKey(bio.get(), NULL, NULL, NULL);
    } else {
      rsa = PEM_read_bio_RSAPrivateKey(bio.get(), NULL, NULL, NULL);
    }
  }

  if (!rsa) {
    ELOG_ERROR("Failed to read PEM key");
    return TEE_ERROR_CRYPTO_RSA_GET_RSA_FROM_KEY;
  }

  rsa_ptr->reset(rsa);
  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::GenerateKeyPair(std::string* public_key,
                                        std::string* private_key) {
  TEE_CATCH_RETURN(
      RsaCrypto::Generate(public_key, private_key, bits_, is_pkcs8_));
  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::Generate(std::string* public_key,
                                 std::string* private_key,
                                 int bit_length,
                                 bool is_pkcs8) {
  uint64_t e = RSA_F4;
  BIGNUM_ptr exp(BN_new(), BN_free);
  if (!exp) {
    ELOG_ERROR("Failed to new big number");
    return TEE_ERROR_CRYPTO_RSA_GENERATE_KEYPAIR;
  }
  if (!BN_set_word(exp.get(), e)) {
    ELOG_ERROR("Failed to set word");
    return TEE_ERROR_CRYPTO_RSA_GENERATE_KEYPAIR;
  }

  RSA_ptr rsa_ptr(RSA_new(), RSA_free);
  if (!rsa_ptr) {
    ELOG_ERROR("Failed to new RSA");
    return TEE_ERROR_CRYPTO_RSA_GENERATE_KEYPAIR;
  }
  if (!RSA_generate_key_ex(rsa_ptr.get(), bit_length, exp.get(), NULL)) {
    ELOG_ERROR("Failed to generate RSA key");
    return TEE_ERROR_CRYPTO_RSA_GENERATE_KEYPAIR;
  }

  TeeErrorCode ret = TEE_ERROR_CRYPTO_RSA;
  ret = RsaCrypto::GetKeyFromRSA(kIsPublicKey, public_key, rsa_ptr, is_pkcs8);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }
  ret = RsaCrypto::GetKeyFromRSA(kIsPrivateKey, private_key, rsa_ptr, is_pkcs8);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::Encrypt(const std::string& public_key,
                                const std::string& src,
                                std::string* dst) {
  if (dst == NULL || public_key.empty() || src.empty()) {
    ELOG_ERROR("Invalid public key for RSA Encrypion");
    return TEE_ERROR_CRYPTO_RSA_PARAMETER;
  }

  // Get RSA key from pem, and check the key size
  RSA_ptr rsa_ptr(NULL, RSA_free);
  TEE_CHECK_RETURN(GetRSAFromKey(kIsPublicKey, public_key, &rsa_ptr));
  int keysize = RSA_size(rsa_ptr.get());
  if (keysize <= 0) {
    ELOG_ERROR("Invalid key size");
    return TEE_ERROR_CRYPTO_RSA_KEY_SIZE;
  }

  // Do decryption in the step of keysize
  dst->clear();
  int pos = 0;
  int length = src.length();
  // See the following for how to select the max size of encrytion len
  // https://www.openssl.org/docs/man1.0.2/man3/RSA_private_decrypt.html
  // Must less than "RSA_size(rsa) - 41"
  int max_enc = keysize - kRSAPaddingSize - 1;
  while (pos < length) {
    DataBytes enc_buf(keysize);
    // Check left
    size_t step_len = (pos + max_enc) <= length ? max_enc : (length - pos);
    std::string step_src = src.substr(pos, step_len);
    // Do encryption
    // return size will be padding to keysize
    int enc_len =
        RSA_public_encrypt(SCAST(int, step_src.length()),
                           RCAST(const unsigned char*, step_src.data()),
                           enc_buf.data(), rsa_ptr.get(), kRSAPaddingScheme);
    if (enc_len != keysize) {
      ERR_load_crypto_strings();
      char error_msg[kErrorBufferLength] = {};
      ERR_error_string(ERR_get_error(), error_msg);
      ELOG_ERROR("Failed to do RSA encryption: %s", error_msg);
      return TEE_ERROR_CRYPTO_RSA_ENCRYPT;
    }
    dst->append(RCAST(char*, enc_buf.data()), enc_buf.size());
    // Go forward
    pos += step_len;
  }

  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::Decrypt(const std::string& private_key,
                                const std::string& src,
                                std::string* dst) {
  if (dst == NULL || private_key.empty() || src.empty()) {
    ELOG_ERROR("Empty private key or plain for RSA decryption");
    return TEE_ERROR_CRYPTO_RSA_PARAMETER;
  }

  // Get RSA key from pem, and check the key size
  RSA_ptr rsa_ptr(NULL, RSA_free);
  TEE_CHECK_RETURN(GetRSAFromKey(kIsPrivateKey, private_key, &rsa_ptr));
  int keysize = RSA_size(rsa_ptr.get());
  if (keysize <= 0) {
    ELOG_ERROR("Invalid key size");
    return TEE_ERROR_CRYPTO_RSA_KEY_SIZE;
  }
  if (src.length() % keysize != 0) {
    ELOG_ERROR("Invalid cipher length for RSA decryption");
    return TEE_ERROR_CRYPTO_RSA_PARAMETER;
  }

  // Do decryption in the step of keysize
  dst->clear();
  int pos = 0;
  int length = src.length();
  while (pos < length) {
    DataBytes dec_buf(keysize);
    // Check left
    int step_len = (pos + keysize) <= length ? keysize : (length - pos);
    std::string step_src = src.substr(pos, step_len);
    // Do decryption
    // return size equal to real plain size, left may less than keysize
    int dec_len =
        RSA_private_decrypt(SCAST(int, step_src.size()),
                            RCAST(const unsigned char*, step_src.data()),
                            dec_buf.data(), rsa_ptr.get(), kRSAPaddingScheme);
    if (dec_len == -1) {
      ERR_load_crypto_strings();
      char error_msg[kErrorBufferLength] = {};
      ERR_error_string(ERR_get_error(), error_msg);
      ELOG_ERROR("Failed to do RSA decryption: %s", error_msg);
      return TEE_ERROR_CRYPTO_RSA_DECRYPT;
    }
    dec_buf.resize(dec_len);
    dst->append(RCAST(char*, dec_buf.data()), dec_len);
    // Go forward
    pos += step_len;
  }

  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::Sign(const std::string& private_key,
                             const std::string& msg,
                             std::string* sigret) {
  if (sigret == NULL || private_key.empty() || msg.empty()) {
    ELOG_ERROR("Invalid private key for RSA sign");
    return TEE_ERROR_CRYPTO_RSA_PARAMETER;
  }

  RSA_ptr rsa_ptr(NULL, RSA_free);
  TeeErrorCode ret = GetRSAFromKey(kIsPrivateKey, private_key, &rsa_ptr);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  DataBytes signature(RSA_size(rsa_ptr.get()));
  DataBytes msg_hash(msg);
  msg_hash.ToSHA256();
  unsigned int sign_size = 0;
  int rsa_ret = RSA_sign(NID_sha256, msg_hash.data(), msg_hash.size(),
                         signature.data(), &sign_size, rsa_ptr.get());
  if (rsa_ret != OPENSSL_SUCCESS) {  // RSA_sign() returns 1 on success
    ERR_load_crypto_strings();
    char error_msg[kErrorBufferLength] = {};
    ERR_error_string(ERR_get_error(), error_msg);
    ELOG_ERROR("Failed to do RSA sign: %s", error_msg);
    return TEE_ERROR_CRYPTO_RSA_SIGN;
  }
  sigret->assign(RCAST(char*, signature.data()), sign_size);
  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::Verify(const std::string& public_key,
                               const std::string& msg,
                               const std::string& sigbuf) {
  if (public_key.empty() || msg.empty() || sigbuf.empty()) {
    ELOG_ERROR("Invalid public key for RSA verify");
    return TEE_ERROR_CRYPTO_RSA_PARAMETER;
  }

  RSA_ptr rsa_ptr(NULL, RSA_free);
  // RSA_free() frees the RSA structure and its components.
  // The key is erased before the memory is returned to the system.
  // If rsa is a NULL pointer, no action occurs.
  TeeErrorCode ret = GetRSAFromKey(kIsPublicKey, public_key, &rsa_ptr);
  if (ret != TEE_SUCCESS) {
    return ret;
  }

  DataBytes msg_hash(msg);
  msg_hash.ToSHA256();
  int rsa_ret = RSA_verify(NID_sha256, msg_hash.data(), msg_hash.size(),
                           RCAST(const uint8_t*, sigbuf.data()),
                           SCAST(uint32_t, sigbuf.length()), rsa_ptr.get());
  if (rsa_ret != OPENSSL_SUCCESS) {
    ERR_load_crypto_strings();
    char error_msg[kErrorBufferLength] = {};
    ERR_error_string(ERR_get_error(), error_msg);
    ELOG_ERROR("Failed to do RSA verify: %s", error_msg);
    return TEE_ERROR_CRYPTO_RSA_VERIFY;
  }

  return TEE_SUCCESS;
}

}  // namespace common
}  // namespace kubetee
