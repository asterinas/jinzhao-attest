#include <cstdint>
#include <string>

#include "openssl/bio.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/pem.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/sm2.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

static constexpr char SM2_ID[] = "1234567812345678";
static constexpr size_t SM2_ID_LEN = 16;

TeeErrorCode SM2Crypto::GenerateKeyPair(std::string* ec_public_key,
                                        std::string* ec_private_key) {
  EC_KEY_ptr ec_key_ptr(EC_KEY_new(), EC_KEY_free);
  EC_GROUP_ptr ec_group_ptr(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);

  if (nullptr == ec_key_ptr.get()) {
    ELOG_ERROR("EC_KEY_new Error");
    return TEE_ERROR_CRYPTO_SM2_PARAM_INIT;
  }

  if (nullptr == ec_group_ptr.get()) {
    ELOG_ERROR("EC_GROUP_new_by_curve_name Error");
    return TEE_ERROR_CRYPTO_SM2_PARAM_INIT;
  }

  if (EC_KEY_set_group(ec_key_ptr.get(), ec_group_ptr.get()) != evp_success) {
    ELOG_ERROR("EC_KEY_set_group Error");
    return TEE_ERROR_CRYPTO_SM2_PARAM_INIT;
  }

  if (!EC_KEY_generate_key(ec_key_ptr.get())) {
    ELOG_ERROR("EC_KEY_generate_key Error");
    return TEE_ERROR_CRYPTO_SM2_KEY;
  }

  BIO_ptr pri_bio(BIO_new(BIO_s_mem()), BIO_free_all);
  BIO_ptr pub_bio(BIO_new(BIO_s_mem()), BIO_free_all);
  int ret = PEM_write_bio_ECPrivateKey(pri_bio.get(), ec_key_ptr.get(), nullptr,
                                       nullptr, 0, nullptr, nullptr);
  if (ret != evp_success) {
    ELOG_ERROR("Failed to write bio EC PrivateKey, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_KEY;
  }

  ret = PEM_write_bio_EC_PUBKEY(pub_bio.get(), ec_key_ptr.get());
  if (ret != evp_success) {
    ELOG_ERROR("Failed to write bio EC PublicKey, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_KEY;
  }

  int private_key_len = BIO_pending(pri_bio.get());
  int public_key_len = BIO_pending(pub_bio.get());
  DataBytes private_key(private_key_len);
  DataBytes public_key(public_key_len);
  BIO_read(pri_bio.get(), private_key.data(), private_key.size());
  BIO_read(pub_bio.get(), public_key.data(), public_key.size());
  ec_private_key->assign(RCAST(char*, private_key.data()), private_key_len);
  ec_public_key->assign(RCAST(char*, public_key.data()), public_key_len);
  return TEE_SUCCESS;
}

TeeErrorCode SM2Crypto::Encrypt(const std::string& ec_public_key,
                                const std::string& src,
                                std::string* dst) {
  EVP_PKEY_ptr pkey_ptr(EVP_PKEY_new(), EVP_PKEY_free);
  TEE_CHECK_RETURN(GetEvpKeyCtxPtr(true, ec_public_key, &pkey_ptr));
  EVP_PKEY_CTX_ptr pctx_ptr(EVP_PKEY_CTX_new(pkey_ptr.get(), nullptr),
                            EVP_PKEY_CTX_free);

  int ret = EVP_PKEY_encrypt_init(pctx_ptr.get());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_PKEY_encrypt_init Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_PARAM_INIT;
  }

  size_t cipher_len;
  ret = EVP_PKEY_encrypt(pctx_ptr.get(), nullptr, &cipher_len,
                         RCAST(const unsigned char*, src.data()), src.length());
  ELOG_INFO("encrypt cipher len = %ld", cipher_len);
  if (ret != evp_success) {
    ELOG_ERROR("EVP_PKEY_encrypt get cipher_len Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_ENCRYPT;
  }

  DataBytes cipher_text(cipher_len);

  ret = EVP_PKEY_encrypt(pctx_ptr.get(), cipher_text.data(), &cipher_len,
                         RCAST(const unsigned char*, src.data()), src.length());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_PKEY_encrypt encrypt data Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_ENCRYPT;
  }

  dst->assign(RCAST(char*, cipher_text.data()), cipher_text.size());
  return TEE_SUCCESS;
}

TeeErrorCode SM2Crypto::Decrypt(const std::string& ec_private_key,
                                const std::string& src,
                                std::string* dst) {
  EVP_PKEY_ptr pkey_ptr(EVP_PKEY_new(), EVP_PKEY_free);
  TEE_CHECK_RETURN(GetEvpKeyCtxPtr(false, ec_private_key, &pkey_ptr));
  EVP_PKEY_CTX_ptr pctx_ptr(EVP_PKEY_CTX_new(pkey_ptr.get(), nullptr),
                            EVP_PKEY_CTX_free);

  int ret = EVP_PKEY_decrypt_init(pctx_ptr.get());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_PKEY_decrypt_init Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_DECRYPT;
  }

  size_t plain_len;
  ret = EVP_PKEY_decrypt(pctx_ptr.get(), nullptr, &plain_len,
                         RCAST(const unsigned char*, src.data()), src.length());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_PKEY_decrypt get plain_len error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_DECRYPT;
  }

  DataBytes plain_text(plain_len);
  ret = EVP_PKEY_decrypt(pctx_ptr.get(), plain_text.data(), &plain_len,
                         RCAST(const unsigned char*, src.data()), src.length());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_PKEY_decrypt decrypt data error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_DECRYPT;
  }

  dst->assign(RCAST(char*, plain_text.data()), plain_len);
  return TEE_SUCCESS;
}

TeeErrorCode SM2Crypto::Sign(const std::string& ec_private_key,
                             const std::string& msg,
                             std::string* signature) {
  EVP_PKEY_ptr pkey_ptr(EVP_PKEY_new(), EVP_PKEY_free);
  TEE_CHECK_RETURN(GetEvpKeyCtxPtr(false, ec_private_key, &pkey_ptr));
  EVP_PKEY_CTX_ptr pctx_ptr(EVP_PKEY_CTX_new(pkey_ptr.get(), nullptr),
                            EVP_PKEY_CTX_free);
  EVP_PKEY_CTX_set1_id(pctx_ptr.get(), SM2_ID, SM2_ID_LEN);

  EVP_MD_CTX_ptr mctx_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (mctx_ptr.get() == nullptr) {
    ELOG_ERROR("EVP_PKEY_CTX_new Error");
    return TEE_ERROR_CRYPTO_SM2_PARAM_INIT;
  }

  EVP_MD_CTX_init(mctx_ptr.get());
  EVP_MD_CTX_set_pkey_ctx(mctx_ptr.get(), pctx_ptr.get());
  int ret = EVP_DigestSignInit(mctx_ptr.get(), nullptr, EVP_sm3(), nullptr,
                               pkey_ptr.get());
  if (ret != evp_success) {
    ELOG_ERROR("Sign EVP_DigestSignInit Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_VERIFY;
  }

  ret = EVP_DigestSignUpdate(mctx_ptr.get(), msg.data(), msg.size());
  if (ret != evp_success) {
    ELOG_ERROR("Sign EVP_DigestSignUpdate Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_VERIFY;
  }

  size_t sig_len;
  ret = EVP_DigestSignFinal(mctx_ptr.get(), nullptr, &sig_len);
  if (ret != evp_success) {
    ELOG_ERROR("Sign EVP_DigestSignFinal get length Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_VERIFY;
  }

  DataBytes signature_bytes(sig_len);
  ELOG_INFO("signature_bytes sig_len = %ld", sig_len);
  ret = EVP_DigestSignFinal(mctx_ptr.get(), signature_bytes.data(), &sig_len);
  if (ret != evp_success) {
    ELOG_ERROR("Sign EVP_DigestSignFinal sign Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_VERIFY;
  }

  signature->assign(RCAST(char*, signature_bytes.data()), sig_len);
  return TEE_SUCCESS;
}

TeeErrorCode SM2Crypto::Verify(const std::string& ec_public_key,
                               const std::string& msg,
                               const std::string& signature) {
  EVP_PKEY_ptr pkey_ptr(EVP_PKEY_new(), EVP_PKEY_free);
  TEE_CHECK_RETURN(GetEvpKeyCtxPtr(true, ec_public_key, &pkey_ptr));
  EVP_PKEY_CTX_ptr pctx_ptr(EVP_PKEY_CTX_new(pkey_ptr.get(), nullptr),
                            EVP_PKEY_CTX_free);
  EVP_PKEY_CTX_set1_id(pctx_ptr.get(), SM2_ID, SM2_ID_LEN);

  EVP_MD_CTX_ptr mctx_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (mctx_ptr.get() == nullptr) {
    ELOG_ERROR("EVP_MD_CTX_new Error");
    return TEE_ERROR_CRYPTO_SM2_PARAM_INIT;
  }

  EVP_MD_CTX_init(mctx_ptr.get());
  EVP_MD_CTX_set_pkey_ctx(mctx_ptr.get(), pctx_ptr.get());
  int ret = EVP_DigestVerifyInit(mctx_ptr.get(), nullptr, EVP_sm3(), nullptr,
                                 pkey_ptr.get());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DigestVerifyInit Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_VERIFY;
  }

  ret = EVP_DigestVerifyUpdate(mctx_ptr.get(), msg.c_str(), msg.length());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DigestVerifyUpdate Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_VERIFY;
  }

  ret = EVP_DigestVerifyFinal(mctx_ptr.get(),
                              (const unsigned char*)signature.c_str(),
                              signature.length());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DigestVerifyFinal Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_VERIFY;
  }

  return TEE_SUCCESS;
}

TeeErrorCode SM2Crypto::GetEvpKeyCtxPtr(bool is_public_key,
                                        const std::string& key,
                                        EVP_PKEY_ptr* evp_key_ptr) {
  BIO* key_bio = BIO_new_mem_buf(key.c_str(), key.length());
  if (key_bio == nullptr) {
    ELOG_ERROR("GetEvpFromKey BIO_new_mem_buf Error");
    return TEE_ERROR_CRYPTO_SM2_KEY;
  }

  if (is_public_key) {
    evp_key_ptr->reset(PEM_read_bio_PUBKEY(key_bio, NULL, NULL, NULL));
  } else {
    evp_key_ptr->reset(PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL));
  }

  BIO_free(key_bio);
  if (evp_key_ptr->get() == nullptr) {
    ELOG_ERROR("GetEvpFromKey BIO_newPEM_read_bio Error");
    return TEE_ERROR_CRYPTO_SM2_KEY;
  }

  int ret = EVP_PKEY_set_alias_type(evp_key_ptr->get(), EVP_PKEY_SM2);
  if (ret != evp_success) {
    ELOG_ERROR("SM2 Encrypt EVP_PKEY_set_alias_type Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SM2_PARAM_INIT;
  }

  return TEE_SUCCESS;
}

}  // namespace common
}  // namespace kubetee
