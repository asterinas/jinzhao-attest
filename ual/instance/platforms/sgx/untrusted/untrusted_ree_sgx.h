#ifndef UAL_INSTANCE_PLATFORMS_SGX_UNTRUSTED_UNTRUSTED_REE_SGX_H_
#define UAL_INSTANCE_PLATFORMS_SGX_UNTRUSTED_UNTRUSTED_REE_SGX_H_

#include <string>

#include "sgx/sgx_urts.h"
#include "sgx/sgx_utils.h"

#include "attestation/common/type.h"
#include "attestation/instance/untrusted_ree_instance_interface.h"

namespace kubetee {
namespace attestation {

// ReeInstanceSgx for generating REE instance for SGX
class ReeInstanceSgx : public ReeInstanceInterface {
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
 private:
  TeeErrorCode EnclaveIdToTeeIdentity(const sgx_enclave_id_t eid,
                                      std::string* tee_identity);
  TeeErrorCode TeeIdentityToEnclaveId(const std::string& tee_identity,
                                      sgx_enclave_id_t* eid);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INSTANCE_PLATFORMS_SGX_UNTRUSTED_UNTRUSTED_REE_SGX_H_
