#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "app/app.h"

int UntrustAuthReportVerify(const std::string& report_json,
                            const std::string& policy_json) {
  // Cannot verify BackgroundCheck type report directly,
  // convert it to Passport type report firstly.
  kubetee::UnifiedAttestationAuthReport auth_report;
  JSON2PB(report_json, &auth_report);
  std::string report_type = auth_report.report().str_report_type();
#ifndef SGX_MODE_SIM
  if (report_type == kUaReportTypeBgcheck) {
    std::string auth_json = report_json;
    kubetee::attestation::ReportConvert covert;
    TEE_CHECK_RETURN(covert.BgcheckToPassportAuthJson(report_json, &auth_json));
    TEE_CHECK_RETURN(UaVerifyAuthReportJson(auth_json, policy_json));
  } else
#endif
  {
    TEE_CHECK_RETURN(UaVerifyAuthReportJson(report_json, policy_json));
  }

  TEE_LOG_INFO("Verify %s type report successfully!", report_type.c_str());
  return 0;
}

int main(int argc, char** argv) {
  // Check the commandline arguments
  std::string report_file;
  std::string policy_file;
  if (argc == 1) {
#ifndef SGX_MODE_SIM
    report_file.assign("unified_attestation_auth_report_Passport.json");
    policy_file.assign("unified_attestation_auth_policy_Passport.json");
#else
    report_file.assign("unified_attestation_auth_report_BackgroundCheck.json");
    policy_file.assign("unified_attestation_auth_policy_BackgroundCheck.json");
#endif
  } else if (argc == 3) {
    report_file.assign(argv[1]);
    policy_file.assign(argv[2]);
  } else {
    printf("Usage: %s [<auth-report-json-file> <policy-json-file>]\n", argv[0]);
    return TEE_ERROR_PARAMETERS;
  }
  TEE_LOG_INFO("Report File: %s", report_file.c_str());
  TEE_LOG_INFO("Policy File: %s", policy_file.c_str());

  // Read authentication report and policy JSON file
  std::string report_json;
  std::string policy_json;
  TEE_CHECK_RETURN(kubetee::utils::FsReadString(report_file, &report_json));
  TEE_CHECK_RETURN(kubetee::utils::FsReadString(policy_file, &policy_json));

  // Verify the reports
  TEE_CHECK_RETURN(UntrustAuthReportVerify(report_json, policy_json));

  return TEE_SUCCESS;
}
