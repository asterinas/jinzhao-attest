#ifndef UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_TEE_INSTANCE_INTERFACE_H_
#define UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_TEE_INSTANCE_INTERFACE_H_

#include <string>

#include "attestation/common/type.h"
#include "attestation/generation/core/generator_interface.h"

namespace kubetee {
namespace attestation {

class TeeInstanceInterface {
 public:
  virtual TeeErrorCode GenerateAuthReport(
      UaReportGenerationParameters* param,
      kubetee::UnifiedAttestationAuthReport* auth) = 0;
  virtual TeeErrorCode ReeRun(const kubetee::UnifiedFunctionParams& params,
                              const google::protobuf::Message& request,
                              google::protobuf::Message* response) = 0;
  // The default way is bound, this is more secure
  virtual TeeErrorCode SealData(const std::string& plain_str,
                                std::string* sealed_str,
                                bool tee_bound = true) = 0;
  virtual TeeErrorCode UnsealData(const std::string& sealed_str,
                                  std::string* plain_str) = 0;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_TEE_INSTANCE_INTERFACE_H_
