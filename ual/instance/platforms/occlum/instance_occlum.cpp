#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <string>

#include "attestation/common/attestation.h"

#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/symmetric_crypto.h"
#include "attestation/common/uak.h"
#include "attestation/instance/trusted_unified_function.h"

#include "utils/untrusted/untrusted_memory.h"

#include "instance/platforms/occlum/instance_occlum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const sgx_key_request_t* key_request;  // Input
  sgx_key_128bit_t* key;                 // Output
} sgxioc_get_key_arg_t;

#define SGXIOC_GET_KEY _IOWR('s', 11, sgxioc_get_key_arg_t)

#ifdef __cplusplus
}
#endif

namespace kubetee {
namespace attestation {

TeeErrorCode InstanceOcclum::GetSealKey(std::string* seal_key,
                                        uint16_t key_policy) {
  int sgx_fd;
  if ((sgx_fd = open("/dev/sgx", O_RDONLY)) < 0) {
    TEE_LOG_ERROR("Failed to open /dev/sgx ");
    return TEE_ERROR_RA_GENERATE_OCCLUM_FILE_OPEN;
  }

  sgx_key_request_t key_request = {0};
  key_request.key_name = SGX_KEYSELECT_SEAL;
  key_request.key_policy = key_policy;
  sgx_key_128bit_t key = {0};
  sgxioc_get_key_arg_t args = {
      .key_request = (const sgx_key_request_t*)&key_request,
      .key = &key,
  };

  TeeErrorCode ret = TEE_SUCCESS;
  int rc = ioctl(sgx_fd, SGXIOC_GET_KEY, &args);
  if (rc < 0) {
    TEE_LOG_ERROR("Failed to get seal key: %d", rc);
    ret = TEE_ERROR_RA_GENERATE_OCCLUM_GET_SEAL_KEY;
  } else {
    seal_key->assign(RCAST(char*, key), 16);
    if (!smMode) {
      seal_key->append(*seal_key);  // extend to 32 bytes for aes_gcm_256
    }
    kubetee::common::DataBytes seal_key_hash(*seal_key);
    TEE_LOG_DEBUG("seal key size: %d", seal_key->size());
    TEE_LOG_DEBUG("seal key HASH: %s", seal_key_hash.GetSHA256HexStr().c_str());
  }

  close(sgx_fd);
  return ret;
}

TeeErrorCode InstanceOcclum::Initialize(const UaTeeInitParameters& param,
                                        std::string* tee_identity) {
  TEE_UNREFERENCED_PARAMETER(param);
  tee_identity->assign(kDummyTeeIdentity);
  return TEE_SUCCESS;
}

TeeErrorCode InstanceOcclum::Finalize(const std::string& tee_identity) {
  return TEE_SUCCESS;
}

TeeErrorCode InstanceOcclum::TeeRun(const std::string& tee_identity,
                                    const std::string& function_name,
                                    const google::protobuf::Message& request,
                                    google::protobuf::Message* response) {
  TEE_UNREFERENCED_PARAMETER(tee_identity);
  TEE_UNREFERENCED_PARAMETER(function_name);
  TEE_UNREFERENCED_PARAMETER(request);
  TEE_UNREFERENCED_PARAMETER(response);
  TEE_LOG_ERROR("Unknow TEE platform");
  return TEE_ERROR_NOT_IMPLEMENTED;
}

TeeErrorCode InstanceOcclum::TeePublicKey(const std::string& tee_identity,
                                          std::string* public_key) {
  TEE_UNREFERENCED_PARAMETER(tee_identity);
  public_key->assign(UakPublic());
  return TEE_SUCCESS;
}

TeeErrorCode InstanceOcclum::SealData(const std::string& tee_identity,
                                      const std::string& plain_str,
                                      std::string* sealed_str,
                                      bool tee_bound) {
  uint16_t key_policy = SGX_KEYPOLICY_MRENCLAVE;
  if (!tee_bound) {
    key_policy = SGX_KEYPOLICY_MRSIGNER;
  }
  std::string seal_key;
  TEE_CHECK_RETURN(GetSealKey(&seal_key, key_policy));

  kubetee::common::SymmetricCrypto sc(seal_key);
  kubetee::UaSealedData sealed;
  TEE_CHECK_RETURN(sc.Encrypt(plain_str, sealed.mutable_cipher()));
  sealed.set_key_policy(key_policy);

  PB2JSON(sealed, sealed_str);
  TEE_LOG_DEBUG("SealData, sealed size: %d", sealed_str->size());
  return TEE_SUCCESS;
}

TeeErrorCode InstanceOcclum::UnsealData(const std::string& tee_identity,
                                        const std::string& sealed_str,
                                        std::string* plain_str) {
  TEE_LOG_DEBUG("UnsealData, sealed size: %d", sealed_str.size());
  kubetee::UaSealedData sealed;
  JSON2PB(sealed_str, &sealed);
  std::string seal_key;
  TEE_CHECK_RETURN(GetSealKey(&seal_key, sealed.key_policy()));

  kubetee::common::SymmetricCrypto sc(seal_key);
  kubetee::SymmetricKeyEncrypted cipher;
  TEE_CHECK_RETURN(sc.Decrypt(sealed.cipher(), plain_str));

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
