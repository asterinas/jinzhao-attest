#ifndef UAL_INSTANCE_PLATFORMS_OCCLUM_INSTANCE_OCCLUM_H_
#define UAL_INSTANCE_PLATFORMS_OCCLUM_INSTANCE_OCCLUM_H_

#include <string>

#include "sgx/sgx_key.h"
#include "sgx/sgx_urts.h"
#include "sgx/sgx_utils.h"

#include "attestation/common/type.h"
#include "attestation/instance/untrusted_ree_instance_interface.h"

namespace kubetee {
namespace attestation {

// InstanceOcclum for managing tee instance in Occlum
class InstanceOcclum : public ReeInstanceInterface {
 public:
  TeeErrorCode Initialize(const UaTeeInitParameters& param,
                          std::string* tee_identity) override;
  TeeErrorCode Finalize(const std::string& tee_identity) override;
  TeeErrorCode TeeRun(const std::string& tee_identity,
                      const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response);
  TeeErrorCode TeePublicKey(const std::string& tee_identity,
                            std::string* public_key) override;
  TeeErrorCode SealData(const std::string& tee_identity,
                        const std::string& plain_str,
                        std::string* sealed_str,
                        bool tee_bound = true) override;
  TeeErrorCode UnsealData(const std::string& tee_identity,
                          const std::string& sealed_str,
                          std::string* plain_str) override;

 private:
  TeeErrorCode GetSealKey(std::string* seal_key, uint16_t key_policy);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INSTANCE_PLATFORMS_OCCLUM_INSTANCE_OCCLUM_H_
