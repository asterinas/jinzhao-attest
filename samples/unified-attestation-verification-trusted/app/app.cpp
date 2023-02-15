#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "app/app.h"

using kubetee::attestation::ReeInstance;
using kubetee::attestation::UaTeeInitParameters;

int SGX_CDECL main(void) {
  // Load the report
#ifndef SGX_MODE_SIM
  std::string filename = "unified_attestation_auth_report_Passport.json";
#else
  std::string filename = "unified_attestation_auth_report_BackgroundCheck.json";
#endif
  std::string auth_json;
  if (kubetee::utils::FsReadString(filename, &auth_json) != 0) {
    printf("Fail to load the report JSON file\n");
  }

  // Create Tee Instance
  std::string tee_identity;
  UaTeeInitParameters param;
  param.trust_application = ENCLAVE;
  TEE_CHECK_RETURN(ReeInstance::Initialize(param, &tee_identity));

  // Ecall and try to do verification
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;
  req.add_argv()->assign(auth_json);
  TEE_CHECK_RETURN(
      ReeInstance::TeeRun(tee_identity, "TrustedVerification", req, &res));
  TEE_LOG_INFO("Do trusted verification successfully!");

  // Destroy enclave instance and exit
  TEE_CHECK_RETURN(ReeInstance::Finalize(tee_identity));

  return TEE_SUCCESS;
}
