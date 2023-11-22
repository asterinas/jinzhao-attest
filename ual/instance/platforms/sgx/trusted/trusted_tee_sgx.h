#ifndef UAL_INSTANCE_PLATFORMS_SGX_TRUSTED_TRUSTED_TEE_SGX_H_
#define UAL_INSTANCE_PLATFORMS_SGX_TRUSTED_TRUSTED_TEE_SGX_H_

#include <string>

#include "./sgx_attributes.h"
#include "./sgx_tseal.h"
#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "attestation/common/type.h"
#include "attestation/instance/trusted_tee_instance_interface.h"

namespace kubetee {
namespace attestation {

// clang-format off

// Copy the following macros from SDK2.5 internal header files to use
// sgx_seal_data_ex with SGX_KEYPOLICY_MRENCLAVE policy. sgx_seal_data
// only support MISIGNER way, which will share data in all the enclaves
// with the same signing key. See also tseal_migration_attr.h
#define FLAGS_NON_SECURITY_BITS (0xFFFFFFFFFFFFC0ULL | \
                                 SGX_FLAGS_MODE64BIT | \
                                 SGX_FLAGS_PROVISION_KEY | \
                                 SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK (~FLAGS_NON_SECURITY_BITS)
#define KEY_POLICY_KSS (SGX_KEYPOLICY_CONFIGID | \
                        SGX_KEYPOLICY_ISVFAMILYID | \
                        SGX_KEYPOLICY_ISVEXTPRODID)
#define MISC_NON_SECURITY_BITS 0x0FFFFFFF
#define TSEAL_DEFAULT_MISCMASK (~MISC_NON_SECURITY_BITS)

// clang-format on

// TeeInstanceSgx for generating REE instance for SGX
class TeeInstanceSgx : public TeeInstanceInterface {
 public:
  TeeErrorCode GenerateAuthReport(
      UaReportGenerationParameters* param,
      kubetee::UnifiedAttestationAuthReport* auth) override;
  TeeErrorCode ReeRun(const kubetee::UnifiedFunctionParams& params,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response) override;
  // The default way is bound, this is more secure
  TeeErrorCode SealData(const std::string& plain_str,
                        std::string* sealed_str,
                        bool tee_bound = true) override;
  TeeErrorCode UnsealData(const std::string& sealed_str,
                          std::string* plain_str) override;

 private:
  TeeErrorCode SealSignerData(const std::string& plain_str,
                              std::string* sealed_str);
  TeeErrorCode SealEnclaveData(const std::string& plain_str,
                               std::string* sealed_str);

  const sgx_attributes_t attributes_ = {TSEAL_DEFAULT_FLAGSMASK, 0x0};
  const sgx_misc_select_t misc_select_ = TSEAL_DEFAULT_MISCMASK;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INSTANCE_PLATFORMS_SGX_TRUSTED_TRUSTED_TEE_SGX_H_
