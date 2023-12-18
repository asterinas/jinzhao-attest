#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "unified_attestation/ua_untrusted.h"

#include "app/app.h"

using kubetee::attestation::ReeInstance;
using kubetee::attestation::UaTeeInitParameters;

int GenerateAuthReportJson(const std::string& report_type) {
  std::string tee_identity;
  UaTeeInitParameters param;
  param.trust_application = ENCLAVE;
  TEE_CHECK_RETURN(ReeInstance::Initialize(param, &tee_identity));

  TeeErrorCode ret = TEE_ERROR_GENERIC;
  do {
    // Generate the unified attestation report
    UaReportGenerationParameters report_param;
    report_param.tee_identity = tee_identity;
    report_param.report_type = report_type;
    TEE_LOG_INFO("Report type: %s", report_type.c_str());
    // Both report nonce and user data use hex string
    // and will be decoded before saved in report.
    // In SGX liked TEE, they are saved into the same place,
    // So we cannot set them at the same tiime
    report_param.report_hex_nonce = "31323334";
    // report_param.others.set_hex_user_data("31323334");
    // Cross test: use user public key for passport type
    if (report_type == kUaReportTypePassport) {
      std::string prvkey;
      std::string pubkey;
      kubetee::common::AsymmetricCrypto::GenerateKeyPair(&pubkey, &prvkey);
      kubetee::common::DataBytes pubkey_hash(pubkey);
      pubkey_hash.ToSHA256().ToHexStr().Void();
      TEE_LOG_INFO("User public key hash: %s", pubkey_hash.GetStr().c_str());
      report_param.others.set_pem_public_key(pubkey);
    }
    std::string auth_json;
    ret = UaGenerateAuthReportJson(&report_param, &auth_json);
    if (ret != 0) {
      TEE_LOG_ERROR("Fail to generate authentication report: 0x%X\n", ret);
      break;
    }

    // Save unified attestation report to local file
    std::string report_filename = "unified_attestation_auth_report_";
    report_filename.append(report_type + ".json");
    ret = kubetee::utils::FsWriteString(report_filename, auth_json);

    // Save unified attestation policy to local file
    kubetee::UnifiedAttestationAuthReport auth_report;
    kubetee::UnifiedAttestationAttributes attr;
    JSON2PB(auth_json, &auth_report);
    TEE_CHECK_RETURN(UaGetAuthReportAttr(auth_report, &attr));
    kubetee::UnifiedAttestationPolicy policy;
    policy.set_pem_public_key(auth_report.pem_public_key());
    policy.add_main_attributes()->CopyFrom(attr);
    std::string policy_json;
    PB2JSON(policy, &policy_json);
    std::string policy_filename = "unified_attestation_auth_policy_";
    policy_filename.append(report_type + ".json");
    ret = kubetee::utils::FsWriteString(policy_filename, policy_json);

    // To test the verify policy interface only
    kubetee::UnifiedAttestationPolicy expected_policy;
    expected_policy.CopyFrom(policy);
    // make some changes
    expected_policy.add_main_attributes()->CopyFrom(
        policy.main_attributes()[0]);
    expected_policy.mutable_main_attributes(1)->clear_hex_ta_measurement();
    TEE_CHECK_RETURN(UaVerifyPolicy(policy, expected_policy));
    TEE_LOG_INFO("Verify policy successfully!");

  } while (0);

  TEE_CHECK_RETURN(ReeInstance::Finalize(tee_identity));
  return ret;
}

int main(int argc, char** argv) {
  // Decide the report types
  std::vector<const char*> types;
  if (argc >= 2) {
    for (int i = 1; i < argc; i++) {
      TEE_LOG_INFO("Add report type[%d] = %s\n", i, argv[i]);
      types.push_back(argv[i]);
    }
  } else {
    types.push_back(kUaReportTypeBgcheck);
#ifndef SGX_MODE_SIM
    // Because Passport type need to connnect third party service
    // So, it's not working for simulation mode
    types.push_back(kUaReportTypePassport);
#endif
  }

  // Generate the reports
  for (auto iter = types.begin(); iter != types.end(); iter++) {
    TeeErrorCode ret = TEE_ERROR_GENERIC;
    if ((ret = GenerateAuthReportJson(*iter))) {
      TEE_LOG_ERROR("GenerateAuthReportJson(%s) failed\n", *iter);
      return ret;
    } else {
      TEE_LOG_INFO("GenerateAuthReportJson(%s) successfully!\n", *iter);
    }
  }
  return 0;
}
