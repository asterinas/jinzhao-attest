#include <memory>
#include <string>

#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"
#include "attestation/instance/untrusted_ree_instance.h"

#ifdef UA_ENV_TYPE_SGXSDK
#include "instance/platforms/sgx/untrusted/untrusted_ree_sgx.h"
#endif

namespace kubetee {
namespace attestation {

/// Static methods
std::shared_ptr<ReeInstanceInterface> ReeInstance::Inner() {
#ifndef UA_ENV_TYPE_SGXSDK
  return std::make_shared<ReeInstanceDummy>();
#else
#ifdef UA_TEE_TYPE_HYPERENCLAVE
  return std::make_shared<ReeInstanceSgx>();
#endif
#ifdef UA_TEE_TYPE_SGX2
  return std::make_shared<ReeInstanceSgx>();
#endif
#ifdef UA_TEE_TYPE_SGX1
  return std::make_shared<ReeInstanceSgx>();
#endif
#endif
  return std::make_shared<ReeInstanceUnknown>();
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

/// Normal methods bound to a instance
TeeErrorCode ReeInstance::Initialize(const UaTeeInitParameters& param) {
  TEE_CHECK_RETURN(ReeInstance::Initialize(param, &tee_identity_));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstance::TeeRun(const std::string& function_name,
                                 const google::protobuf::Message& request,
                                 google::protobuf::Message* response) {
  TEE_CHECK_RETURN(ReeInstance::TeeRun(tee_identity_, function_name, request, response));
  return TEE_SUCCESS;
}

TeeErrorCode ReeInstance::TeePublicKey(std::string* public_key) {
  TEE_CHECK_RETURN(ReeInstance::TeePublicKey(tee_identity_, public_key));
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
