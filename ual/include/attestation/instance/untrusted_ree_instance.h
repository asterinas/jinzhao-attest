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
  // Static methods, should not use it based on a instance
  static TeeErrorCode Initialize(const UaTeeInitParameters& param,
                                 std::string* tee_identity);
  static TeeErrorCode Finalize(const std::string& tee_identit);
  static TeeErrorCode TeeRun(const std::string& tee_identity,
                             const std::string& function_name,
                             const google::protobuf::Message& request,
                             google::protobuf::Message* response);
  static TeeErrorCode TeePublicKey(const std::string& tee_identity,
                                   std::string* public_key);
  static TeeErrorCode SealData(const std::string& tee_identity,
                               const std::string& plain_str,
                               std::string* sealed_str,
                               bool tee_bound = true);
  static TeeErrorCode UnsealData(const std::string& tee_identity,
                                 const std::string& sealed_str,
                                 std::string* plain_str);

  // Normal methods bound to a instance
  ReeInstance() {}
  ReeInstance(const std::string& enclave_name) {
    UaTeeInitParameters param;
    param.trust_application = enclave_name;
    Initialize(param, &tee_identity_);
  }
  ~ReeInstance() {
    (void)ReeInstance::Finalize(tee_identity_);
  }

  TeeErrorCode Initialize(const UaTeeInitParameters& param);
  TeeErrorCode TeeRun(const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response);
  TeeErrorCode TeePublicKey(std::string* public_key);
  TeeErrorCode SealData(const std::string& plain_str,
                        std::string* sealed_str,
                        bool tee_bound = true);
  TeeErrorCode UnsealData(const std::string& sealed_str,
                          std::string* plain_str);

  const std::string& TeeIdentity() {
    return tee_identity_;
  }

 private:
  static std::shared_ptr<ReeInstanceInterface> Inner();

  // This only used in non-static methods
  std::string tee_identity_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_REE_INSTANCE_H_
