#include <string>

#include "attestation/common/asymmetric_crypto.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"

namespace kubetee {
namespace attestation {

// Used in GetInstance and all pubcli methods.
UA_MUTEX_T UaIdentityKey::uak_lock_ = UA_MUTEX_INITIALIZER;

/// Private methods
void UaIdentityKey::Initialize() {
  if (uak_.private_key().empty() || uak_.public_key().empty()) {
    ELOG_INFO("Initialize UAK ...");
    if (TEE_SUCCESS !=
        kubetee::common::AsymmetricCrypto::GenerateKeyPair(
            uak_.mutable_public_key(), uak_.mutable_private_key())) {
      ELOG_ERROR("Fail to initialize UAK!");
    }
  }
}

TeeErrorCode UaIdentityKey::UpdateUak(const std::string& private_key,
                                      const std::string& public_key) {
  if (private_key.empty() || public_key.empty()) {
    ELOG_ERROR("Empty key when set UAK");
    return TEE_ERROR_RA_UAK_SET_KEYPAIR;
  }
  UA_MUTEX_LOCK(&uak_lock_);
  uak_.set_public_key(public_key);
  uak_.set_private_key(private_key);
  UA_MUTEX_UNLOCK(&uak_lock_);
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee

#ifdef __cplusplus
extern "C" {
#endif

using kubetee::attestation::UaIdentityKey;

TeeErrorCode UakUpdate(const std::string& private_key,
                       const std::string& public_key) {
  return UaIdentityKey::GetInstance().UpdateUak(private_key, public_key);
}

const kubetee::AsymmetricKeyPair& Uak() {
  return UaIdentityKey::GetInstance().Uak();
}

const std::string& UakPrivate() {
  return UaIdentityKey::GetInstance().Uak().private_key();
}

const std::string& UakPublic() {
  return UaIdentityKey::GetInstance().Uak().public_key();
}

/// APIs for C code
int UnifiedAttestationUpdateUak(const char* private_key_str,
                                const char* public_key_str) {
  std::string private_key(SAFESTR(private_key_str));
  std::string public_key(SAFESTR(public_key_str));
  return UakUpdate(private_key, public_key);
}

int UnifiedAttestationUakPrivate(char* private_key_buf, int* private_key_len) {
  TEE_CHECK_VALIDBUF(private_key_buf, *private_key_len);
  const std::string& private_key = UakPrivate();
  if (private_key.size() >= SCAST(size_t, *private_key_len)) {
    return TEE_ERROR_RA_UAK_SMALLER_BUFFER;
  }
  memcpy(private_key_buf, private_key.data(), private_key.size());
  *private_key_len = SCAST(int, private_key.size());
  return TEE_SUCCESS;
}

int UnifiedAttestationUakPublic(char* public_key_buf, int* public_key_len) {
  TEE_CHECK_VALIDBUF(public_key_buf, *public_key_len);
  const std::string& public_key = UakPublic();
  if (public_key.size() >= SCAST(size_t, *public_key_len)) {
    return TEE_ERROR_RA_UAK_SMALLER_BUFFER;
  }
  memcpy(public_key_buf, public_key.data(), public_key.size());
  *public_key_len = SCAST(size_t, public_key.size());
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
