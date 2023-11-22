#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "app/app.h"

TeeErrorCode SealUnsealCpp() {
  kubetee::attestation::ReeInstance instance(ENCLAVE);
  std::string plain_str = "1234";
  std::string sealed_str;
  std::string unsealed_str;
  TEE_CHECK_RETURN(instance.SealData(plain_str, &sealed_str));
  TEE_CHECK_RETURN(instance.UnsealData(sealed_str, &unsealed_str));
  TEE_LOG_INFO("SealUnsealCpp, plain   : %s", plain_str.c_str());
  TEE_LOG_INFO("SealUnsealCpp, unsealed: %s", unsealed_str.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode SealUnsealC() {
  // Create Enclave instance
  kubetee::attestation::UaTeeInitParameters param;
  param.trust_application = ENCLAVE;
  std::string tee_identity;
  TEE_CHECK_RETURN(kubetee::attestation::ReeInstance::Initialize(
      param, &tee_identity));

  // Seal data
  char z = '\0';
  std::string plain_str = "1234";
  std::string sealed_str(2048, z);  // the total sealed str is 1128 bytes
  std::string unsealed_str(plain_str.size() + 1, z);
  unsigned int sealed_size = SCAST(unsigned int, sealed_str.size());
  unsigned int unsealed_size = SCAST(unsigned int, unsealed_str.size());
  TEE_CHECK_RETURN(UnifiedAttestationSealData(tee_identity.data(),
      plain_str.data(), SCAST(unsigned int, plain_str.size()), 
      CCAST(char*, sealed_str.data()), &sealed_size, false));
  sealed_str.resize(sealed_size);

  // Unseal data
  TEE_CHECK_RETURN(UnifiedAttestationUnsealData(tee_identity.data(),
      sealed_str.data(), SCAST(unsigned int, sealed_str.size()),
      CCAST(char*, unsealed_str.data()), &unsealed_size));
  unsealed_str.resize(unsealed_size);
  TEE_LOG_INFO("SealUnsealC, plain   : %s", plain_str.c_str());
  TEE_LOG_INFO("SealUnsealC, unsealed: %s", unsealed_str.c_str());

  // Destroy Enclave instance
  TEE_CHECK_RETURN(kubetee::attestation::ReeInstance::Finalize(tee_identity));
  return TEE_SUCCESS;
}

int main(int argc, char** argv) {
  TEE_CHECK_RETURN(SealUnsealCpp());
  TEE_CHECK_RETURN(SealUnsealC());
  return TEE_SUCCESS;
}
