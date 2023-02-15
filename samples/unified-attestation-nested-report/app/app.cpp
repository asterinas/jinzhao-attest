#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "app/app.h"

using kubetee::attestation::ReeInstance;

static int g_report_index = 1;

static TeeErrorCode GenerateSubmoduleAuthReportJson(
    std::string* json_auth_report) {
  kubetee::attestation::ReeInstance ree;
  kubetee::attestation::UaTeeInitParameters param;
  param.trust_application = ENCLAVE;
  TEE_CHECK_RETURN(ree.Initialize(param));

  // Call the TeeInstanceUpdateReportData() in enclave side
  // So, the untrusted user_data here will be ignored.
  std::string report_index = "99" + std::to_string(g_report_index++);
  kubetee::common::DataBytes hex_user_data(report_index);
  TEE_CHECK_RETURN(hex_user_data.ToHexStr().GetError());
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;
  req.add_argv(hex_user_data.GetStr());
  TEE_CHECK_RETURN(ree.TeeRun("SampleEnclaveInit", req, &res));

  // Generate the unified attestation report
  UaReportGenerationParameters report_param;
  report_param.tee_identity = ree.TeeIdentity();
  report_param.report_type = kUaReportTypePassport;
  TEE_CHECK_RETURN(UaGenerateAuthReportJson(&report_param, json_auth_report));

  return TEE_SUCCESS;
}

static TeeErrorCode VerifySubReports(const std::string& tee_identity,
                                     std::string* nested_reports_str) {
  // Generate the submodule attester1 reports
  std::string sub1_report;
  TEE_CHECK_RETURN(GenerateSubmoduleAuthReportJson(&sub1_report));
  TEE_LOG_INFO("GenerateSubmoduleAuthReportJson sub2 successfully!");
  // Generate the submodule attester2 reports
  std::string sub2_report;
  TEE_CHECK_RETURN(GenerateSubmoduleAuthReportJson(&sub2_report));
  TEE_LOG_INFO("GenerateSubmoduleAuthReportJson sub2 successfully!");
  // Prepare all the submodules auth reports
  kubetee::UnifiedAttestationAuthReports auth_reports;
  auth_reports.add_reports(sub1_report);
  auth_reports.add_reports(sub2_report);

  // Prepare the nested submodule attester verification policy
  kubetee::UnifiedAttestationPolicy policy;
  kubetee::UnifiedAttestationNestedPolicy* sub_attester1 =
      policy.add_nested_policies();
  kubetee::UnifiedAttestationAttributes* attr11 =
      sub_attester1->add_sub_attributes();
  attr11->set_hex_ta_measurement("");
  attr11->set_hex_signer("");
  attr11->set_hex_prod_id("");
  attr11->set_str_min_isvsvn("");
  attr11->set_bool_debug_disabled("");
  attr11->set_str_tee_platform("");
  attr11->set_hex_spid("");
  attr11->set_str_tee_platform("");
  attr11->set_hex_user_data("393931");

  kubetee::UnifiedAttestationNestedPolicy* sub_attester2 =
      policy.add_nested_policies();
  kubetee::UnifiedAttestationAttributes* attr21 =
      sub_attester2->add_sub_attributes();
  attr21->CopyFrom(*attr11);
  attr21->set_hex_user_data("393932");

  // Verify the submodule attester locally firstly
  TEE_CHECK_RETURN(UaGenerationVerifySubReports(tee_identity, auth_reports,
                                                policy, nested_reports_str));
  TEE_LOG_INFO("UaGenerationVerifySubReports successfully!");

  return TEE_SUCCESS;
}

static TeeErrorCode GenerateMainAuthReportJson(std::string* auth_json) {
  kubetee::attestation::ReeInstance ree;
  kubetee::attestation::UaTeeInitParameters param;
  param.trust_application = ENCLAVE;
  TEE_CHECK_RETURN(ree.Initialize(param));

  std::string nested_reports;
  TEE_CHECK_RETURN(VerifySubReports(ree.TeeIdentity(), &nested_reports));

  // Call the TeeInstanceSetReportData() in enclave side
  // So, the untrusted user_data here will be ignored.
  std::string report_index = "99" + std::to_string(g_report_index++);
  kubetee::common::DataBytes hex_user_data(report_index);
  TEE_CHECK_RETURN(hex_user_data.ToHexStr().GetError());
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;
  req.add_argv(hex_user_data.GetStr());
  TEE_CHECK_RETURN(ree.TeeRun("SampleEnclaveInit", req, &res));

  // Generate the main unified attestation report
  UaReportGenerationParameters report_param;
  report_param.tee_identity = ree.TeeIdentity();
  report_param.report_type = kUaReportTypePassport;
  report_param.others.set_json_nested_reports(nested_reports);
  TEE_CHECK_RETURN(UaGenerateAuthReportJson(&report_param, auth_json));

  return TEE_SUCCESS;
}

int main(int argc, char** argv) {
  // Generate the main enclave report with nested enclaves
  std::string main_report;
  TEE_CHECK_RETURN(GenerateMainAuthReportJson(&main_report));
  TEE_LOG_INFO("GenerateMainAuthReportJson successfully!");

  // Prepare the nested report verification policy
  // Only verify the user_data here as example
  // Must set other necessary attributes in real product code.
  kubetee::UnifiedAttestationPolicy policy;
  kubetee::UnifiedAttestationAttributes* attr = policy.add_main_attributes();
  attr->set_hex_user_data("393933");
  kubetee::UnifiedAttestationNestedPolicy* nested_policy1 =
      policy.add_nested_policies();
  kubetee::UnifiedAttestationAttributes* attr1 =
      nested_policy1->add_sub_attributes();
  attr1->set_hex_user_data("393931");
  kubetee::UnifiedAttestationNestedPolicy* nested_policy2 =
      policy.add_nested_policies();
  kubetee::UnifiedAttestationAttributes* attr2 =
      nested_policy2->add_sub_attributes();
  attr2->set_hex_user_data("393932");

  // Verify the main enclave report int untrusted part directly
  std::string policy_json;
  PB2JSON(policy, &policy_json);
  TEE_LOG_INFO("Nested report verify policy:\n%s", policy_json.c_str());
  TEE_CHECK_RETURN(UaVerifyAuthReportJson(main_report, policy_json));
  TEE_LOG_INFO("UaVerifyAuthReportJson successfully!");

  return 0;
}
