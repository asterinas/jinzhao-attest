#ifndef UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_REE_INSTANCE_H_
#define UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_REE_INSTANCE_H_

#include <memory>
#include <string>

#include "attestation/common/attestation.h"
#include "attestation/common/type.h"
#include "attestation/instance/untrusted_ree_instance_interface.h"

namespace kubetee {
namespace attestation {

// TeeInstance create or destroy a TEE instance.
class ReeInstance {
 public:
  // Static methods
  static TeeErrorCode Initialize(const UaTeeInitParameters& param,
                                 std::string* tee_identity);
  static TeeErrorCode Finalize(const std::string& tee_identit);
  static TeeErrorCode TeeRun(const std::string& tee_identity,
                             const std::string& function_name,
                             const google::protobuf::Message& request,
                             google::protobuf::Message* response);
  static TeeErrorCode TeePublicKey(const std::string& tee_identity,
                                   std::string* public_key);

  // Normal methods bound to a instance
  ReeInstance() {}
  ~ReeInstance() {
    (void)ReeInstance::Finalize(tee_identity_);
  }

  TeeErrorCode Initialize(const UaTeeInitParameters& param);
  TeeErrorCode TeeRun(const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response);
  TeeErrorCode TeePublicKey(std::string* public_key);

  const std::string& TeeIdentity() {
    return tee_identity_;
  }

 private:
  static std::shared_ptr<ReeInstanceInterface> Inner();

  // This only used in non-static methods
  std::string tee_identity_;
};

// TeeInstanceUnkown for reporting error
class ReeInstanceUnknown : public ReeInstanceInterface {
 public:
  TeeErrorCode Initialize(const UaTeeInitParameters& param,
                          std::string* tee_identity) override {
    TEE_UNREFERENCED_PARAMETER(param);
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_CREATE_ENCLAVE;
  }

  TeeErrorCode TeeRun(const std::string& tee_identity,
                      const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_UNREFERENCED_PARAMETER(function_name);
    TEE_UNREFERENCED_PARAMETER(request);
    TEE_UNREFERENCED_PARAMETER(response);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_NOT_IMPLEMENTED;
  }
  TeeErrorCode TeePublicKey(const std::string& tee_identity,
                            std::string* public_key) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_UNREFERENCED_PARAMETER(public_key);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_RA_GET_PUBLIC_KEY;
  }

  TeeErrorCode Finalize(const std::string& tee_identity) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_DESTROY_ENCLAVE_FAILED;
  }
};

#ifndef UA_ENV_TYPE_SGXSDK
#include "attestation/common/uak.h"

// TeeInstanceOcclum for compatbility in Occlum
class ReeInstanceDummy : public ReeInstanceInterface {
 public:
  TeeErrorCode Initialize(const UaTeeInitParameters& param,
                          std::string* tee_identity) override {
    TEE_UNREFERENCED_PARAMETER(param);
    tee_identity->assign(kDummyTeeIdentity);
    return TEE_SUCCESS;
  }

  TeeErrorCode TeeRun(const std::string& tee_identity,
                      const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_UNREFERENCED_PARAMETER(function_name);
    TEE_UNREFERENCED_PARAMETER(request);
    TEE_UNREFERENCED_PARAMETER(response);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_NOT_IMPLEMENTED;
  }

  TeeErrorCode TeePublicKey(const std::string& tee_identity,
                            std::string* public_key) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    public_key->assign(UakPublic());
    return TEE_SUCCESS;
  }

  TeeErrorCode Finalize(const std::string& tee_identity) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    return TEE_SUCCESS;
  }
};
#endif

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_REE_INSTANCE_H_
