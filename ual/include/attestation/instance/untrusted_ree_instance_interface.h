#ifndef UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_REE_INSTANCE_INTERFACE_H_
#define UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_REE_INSTANCE_INTERFACE_H_

#include <string>

#include "attestation/common/type.h"

namespace kubetee {
namespace attestation {

typedef struct {
  // The name of the trusted application file
  std::string trust_application;
} UaTeeInitParameters;

class ReeInstanceInterface {
 public:
  virtual TeeErrorCode Initialize(const UaTeeInitParameters& param,
                                  std::string* tee_identity) = 0;
  virtual TeeErrorCode Finalize(const std::string& tee_identity) = 0;
  virtual TeeErrorCode TeeRun(const std::string& tee_identity,
                              const std::string& function_name,
                              const google::protobuf::Message& request,
                              google::protobuf::Message* response) = 0;
  virtual TeeErrorCode TeePublicKey(const std::string& tee_identity,
                                    std::string* public_key) = 0;
  virtual ~ReeInstanceInterface() = default;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_REE_INSTANCE_INTERFACE_H_
