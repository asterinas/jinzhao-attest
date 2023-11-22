#include <memory>
#include <string>

#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"
#include "attestation/instance/untrusted_ree_instance.h"

#ifdef UA_ENV_TYPE_SGXSDK
#include "instance/platforms/sgx/untrusted/untrusted_ree_sgx.h"
#endif
#ifdef UA_ENV_TYPE_OCCLUM
#include "instance/platforms/occlum/instance_occlum.h"
#endif

namespace kubetee {
namespace attestation {

/// Static methods
std::shared_ptr<ReeInstanceInterface> ReeInstance::Inner() {
#ifdef UA_ENV_TYPE_SGXSDK
#ifdef UA_TEE_TYPE_HYPERENCLAVE
  return std::make_shared<ReeInstanceSgx>();
#endif
#ifdef UA_TEE_TYPE_SGX2
  return std::make_shared<ReeInstanceSgx>();
#endif
#ifdef UA_TEE_TYPE_SGX1
  return std::make_shared<ReeInstanceSgx>();
#endif
#elif defined(UA_ENV_TYPE_OCCLUM)
  return std::make_shared<InstanceOcclum>();
#else
  return std::make_shared<ReeInstanceUnknown>();
#endif
}

TeeErrorCode ReeInstance::Initialize(const UaTeeInitParameters& param,
                                     std::string* tee_identity) {
  return Inner()->Initialize(param, tee_identity);
}

TeeErrorCode ReeInstance::Finalize(const std::string& tee_identity) {
  return Inner()->Finalize(tee_identity);
}

TeeErrorCode ReeInstance::TeeRun(const std::string& tee_identity,
                                 const std::string& function_name,
                                 const google::protobuf::Message& request,
                                 google::protobuf::Message* response) {
  return Inner()->TeeRun(tee_identity, function_name, request, response);
}

TeeErrorCode ReeInstance::TeePublicKey(const std::string& tee_identity,
                                       std::string* public_key) {
  return Inner()->TeePublicKey(tee_identity, public_key);
}

TeeErrorCode ReeInstance::SealData(const std::string& tee_identity,
                                   const std::string& plain_str,
                                   std::string* sealed_str,
                                   bool tee_bound) {
  return Inner()->SealData(tee_identity, plain_str, sealed_str, tee_bound);
}

TeeErrorCode ReeInstance::UnsealData(const std::string& tee_identity,
                                     const std::string& sealed_str,
                                     std::string* plain_str) {
  return Inner()->UnsealData(tee_identity, sealed_str, plain_str);
}

/// Normal methods bound to a instance
TeeErrorCode ReeInstance::Initialize(const UaTeeInitParameters& param) {
  TEE_CHECK_RETURN(ReeInstance::Initialize(param, &tee_identity_));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstance::TeeRun(const std::string& function_name,
                                 const google::protobuf::Message& request,
                                 google::protobuf::Message* response) {
  TEE_CHECK_RETURN(
      ReeInstance::TeeRun(tee_identity_, function_name, request, response));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstance::TeePublicKey(std::string* public_key) {
  TEE_CHECK_RETURN(ReeInstance::TeePublicKey(tee_identity_, public_key));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstance::SealData(const std::string& plain_str,
                                   std::string* sealed_str,
                                   bool tee_bound) {
  TEE_CHECK_RETURN(
      ReeInstance::SealData(tee_identity_, plain_str, sealed_str, tee_bound));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstance::UnsealData(const std::string& sealed_str,
                                     std::string* plain_str) {
  TEE_CHECK_RETURN(
      ReeInstance::UnsealData(tee_identity_, sealed_str, plain_str));
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
