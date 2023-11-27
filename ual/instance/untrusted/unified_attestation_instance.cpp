#include <memory>
#include <string>

#include "attestation/common/log.h"
#include "attestation/common/type.h"

#include "attestation/instance/unified_attestation_instance.h"
#include "attestation/instance/untrusted_ree_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

int UnifiedAttestationSealData(const char* tee_identity,
                               const char* plain_buf,
                               const unsigned int plain_size,
                               char* sealed_buf,
                               unsigned int* sealed_size,
                               bool tee_bound) {
  TEE_CHECK_VALIDBUF(plain_buf, plain_size);
  TEE_CHECK_VALIDBUF(sealed_buf, *sealed_size);
  std::string identity_str;
  if (tee_identity == NULL) {
    identity_str = kDummyTeeIdentity;
  } else {
    identity_str.assign(tee_identity);
  }

  std::string plain_str(plain_buf, plain_size);
  std::string sealed_str;
  TEE_CHECK_RETURN(kubetee::attestation::ReeInstance::SealData(
      identity_str, plain_str, &sealed_str, tee_bound));
  if (*sealed_size <= sealed_str.size()) { //reserve one bytes for '\0'
     TEE_LOG_ERROR("Too smaller seal data out buffer: %d/%d", *sealed_size,
        sealed_str.size());
    return TEE_ERROR_SEAL_DATA_BUFFER_SIZE;
  }

  memcpy(RCAST(void*, sealed_buf), sealed_str.data(), sealed_str.size());
  *sealed_size = sealed_str.size();
  return TEE_SUCCESS;
}

int UnifiedAttestationUnsealData(const char* tee_identity,
                                 const char* sealed_buf,
                                 const unsigned int sealed_size,
                                 char* plain_buf,
                                 unsigned int* plain_size) {
  TEE_CHECK_VALIDBUF(sealed_buf, sealed_size);
  TEE_CHECK_VALIDBUF(plain_buf, *plain_size);
  std::string identity_str;
  if (tee_identity == NULL) {
    identity_str = kDummyTeeIdentity;
  } else {
    identity_str.assign(tee_identity);
  }

  std::string sealed_str(sealed_buf, sealed_size);
  std::string plain_str;
  TEE_CHECK_RETURN(kubetee::attestation::ReeInstance::UnsealData(
      identity_str, sealed_str, &plain_str));
  if (*plain_size <= plain_str.size()) { //reserve one bytes for '\0'
     TEE_LOG_ERROR("Too smaller unseal data out buffer: %d/%d", *plain_size,
        plain_str.size());
    return TEE_ERROR_UNSEAL_DATA_BUFFER_SIZE;
  }

  memcpy(RCAST(void*, plain_buf), plain_str.data(), plain_str.size());
  *plain_size = plain_str.size();
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
