#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "app/app.h"

using kubetee::attestation::ReeInstance;

static int g_report_index = 1;
static const char kGroupName[] = "test-group";
static const char kGroupID[] = "5f3b66f3-e00f-4fd3-ae57-296ccb4c9c58";

// We assume that all submodule attester report have already been verified.
// And this code to prepare and sign nested reports shoul be in TEE.
static TeeErrorCode PrepareNestedReports(std::string* json_nested_reports) {
  kubetee::UnifiedAttestationNestedResults nested_results;

  // Set group name and ID
  nested_results.set_str_group_name(kGroupName);
  nested_results.set_str_group_id(kGroupID);

  // Set the submodule attester1
  kubetee::UnifiedAttestationNestedResult* nested_result1 =
      nested_results.add_results();
  kubetee::UnifiedAttestationAttributes* attr1 =
      nested_result1->mutable_result();
  attr1->set_str_tee_name("App1");
  attr1->set_hex_user_data("393931");

  // Set the submodule attester2
  kubetee::UnifiedAttestationNestedResult* nested_result2 =
      nested_results.add_results();
  kubetee::UnifiedAttestationAttributes* attr2 =
      nested_result2->mutable_result();
  attr2->set_str_tee_name("App2");
  attr2->set_hex_user_data("393932");

  kubetee::UnifiedAttestationNestedReports nested_reports;
  PB2JSON(nested_results, nested_reports.mutable_json_nested_results());

  // Add the signature of submodule enclaves
  std::string signature;
  TEE_CHECK_RETURN(kubetee::common::RsaCrypto::Sign(
      UakPrivate(), nested_reports.json_nested_results(), &signature));
  kubetee::common::DataBytes b64_signature(signature);
  nested_reports.set_b64_nested_signature(b64_signature.ToBase64().GetStr());

  PB2JSON(nested_reports, json_nested_reports);
  return TEE_SUCCESS;
}

static TeeErrorCode PrepareNestedPolicies(
    kubetee::UnifiedAttestationNestedPolicies* nested_policies) {
  // Set group name and ID
  nested_policies->set_str_group_name(kGroupName);
  nested_policies->set_str_group_id(kGroupID);

  // Set the submodule attester1
  kubetee::UnifiedAttestationNestedPolicy* nested_policy1 =
      nested_policies->add_policies();
  kubetee::UnifiedAttestationAttributes* attr1 =
      nested_policy1->add_sub_attributes();
  attr1->set_str_tee_name("App1");
  attr1->set_hex_user_data("393931");

  // Set the submodule attester2
  kubetee::UnifiedAttestationNestedPolicy* nested_policy2 =
      nested_policies->add_policies();
  kubetee::UnifiedAttestationAttributes* attr2 =
      nested_policy2->add_sub_attributes();
  attr2->set_str_tee_name("App2");
  attr2->set_hex_user_data("393932");

  return TEE_SUCCESS;
}

int main(int argc, char** argv) {
  // Prepare nested reports
  std::string json_nested_reports;
  TEE_CHECK_RETURN(PrepareNestedReports(&json_nested_reports));

  // Generate the main enclave report with nested results
  const std::string main_user_data = "393933";
  UaReportGenerationParameters param;
  param.tee_identity = kDummyTeeIdentity;
  param.report_type = kUaReportTypePassport;
  param.others.set_json_nested_reports(json_nested_reports);
  param.others.set_hex_user_data(main_user_data);
  kubetee::UnifiedAttestationAuthReport report;
  TEE_CHECK_RETURN(UaGenerateAuthReport(&param, &report));
  TEE_LOG_INFO("Generate nested auth report successfully!");

  // Prepare the nested report verification policy
  // Only verify the user_data here as example
  // Must set other necessary attributes in real product code.
  kubetee::UnifiedAttestationPolicy policy;
  kubetee::UnifiedAttestationAttributes* main_attr =
      policy.add_main_attributes();
  main_attr->set_hex_user_data(main_user_data);
  // Prepare the nested policies
  TEE_CHECK_RETURN(PrepareNestedPolicies(policy.mutable_nested_policies()));
  std::string policy_json;
  PB2JSON(policy, &policy_json);
  TEE_LOG_INFO("Nested policy:\n%s", policy_json.c_str());

  // Verify the main enclave report int untrusted part directly
  TEE_CHECK_RETURN(UaVerifyAuthReport(report, policy));
  TEE_LOG_INFO("Verify nested auth report successfully!");

  return 0;
}
