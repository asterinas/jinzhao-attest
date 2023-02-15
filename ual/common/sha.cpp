#include <cstdint>
#include <string>

#include "openssl/evp.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/sha.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

TeeErrorCode Sha::sha256(const std::string& message, std::string* hash) {
  return calHash(message, EVP_sha256(), hash);
}

TeeErrorCode Sha::calHash(const std::string& message,
                          const EVP_MD* type,
                          std::string* hash) {
  EVP_MD_CTX_ptr evp_md_ctx_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (evp_md_ctx_ptr.get() == nullptr) {
    ELOG_ERROR("EVP_MD_CTX_new Error");
    return TEE_ERROR_CRYPTO_SHA_EVP_CTX;
  }

  int ret = EVP_DigestInit_ex(evp_md_ctx_ptr.get(), type, nullptr);
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DigestInit_ex Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SHA_INIT;
  }

  ret = EVP_DigestUpdate(evp_md_ctx_ptr.get(), (const char*)message.c_str(),
                         message.length());
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DigestUpdate Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SHA_UPDATE;
  }

  unsigned int max_hash_size = 128;
  unsigned char hash_buf[max_hash_size];
  ret = EVP_DigestFinal_ex(evp_md_ctx_ptr.get(), hash_buf, &max_hash_size);
  if (ret != evp_success) {
    ELOG_ERROR("EVP_DigestFinal_ex Error, ret = %d", ret);
    return TEE_ERROR_CRYPTO_SHA_FINAL;
  }
  std::string hash_str((const char*)hash_buf, max_hash_size);
  hash->assign(hash_str);

  return TEE_SUCCESS;
}

}  // namespace common
}  // namespace kubetee
