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
  virtual TeeErrorCode SealData(const std::string& tee_identity,
                                const std::string& plain_str,
                                std::string* sealed_str,
                                bool tee_bound = true) = 0;
  virtual TeeErrorCode UnsealData(const std::string& tee_identity,
                                  const std::string& sealed_str,
                                  std::string* plain_str) = 0;
  virtual ~ReeInstanceInterface() = default;
};

// TeeInstanceUnkown for unknown TEE platform
class ReeInstanceUnknown : public ReeInstanceInterface {
 public:
  TeeErrorCode Initialize(const UaTeeInitParameters& param,
                          std::string* tee_identity) override {
    TEE_UNREFERENCED_PARAMETER(param);
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_CREATE_ENCLAVE;
  }

  TeeErrorCode Finalize(const std::string& tee_identity) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_DESTROY_ENCLAVE_FAILED;
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

  TeeErrorCode SealData(const std::string& tee_identity,
                        const std::string& plain_str,
                        std::string* sealed_str,
                        bool tee_bound = true) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_UNREFERENCED_PARAMETER(plain_str);
    TEE_UNREFERENCED_PARAMETER(sealed_str);
    TEE_UNREFERENCED_PARAMETER(tee_bound);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_NOT_IMPLEMENTED;
  }

  TeeErrorCode UnsealData(const std::string& tee_identity,
                          const std::string& sealed_str,
                          std::string* plain_str) override {
    TEE_UNREFERENCED_PARAMETER(tee_identity);
    TEE_UNREFERENCED_PARAMETER(sealed_str);
    TEE_UNREFERENCED_PARAMETER(plain_str);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_NOT_IMPLEMENTED;
  }
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_REE_INSTANCE_INTERFACE_H_
