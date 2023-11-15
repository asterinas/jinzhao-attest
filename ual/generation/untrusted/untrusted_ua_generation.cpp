#include <map>
#include <string>

#include "sgx_urts.h"

#include "attestation/common/attestation.h"
#include "attestation/common/bytes.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/uak.h"
#include "attestation/generation/core/generator.h"
#include "attestation/generation/ua_generation.h"
#include "attestation/generation/unified_attestation_generation.h"
#include "attestation/instance/untrusted_ree_instance.h"
#include "attestation/verification/ua_verification.h"

#include "utils/untrusted/untrusted_ua_config.h"

#ifdef __cplusplus
extern "C" {
#endif

static std::string GetSpid() {
  return UA_ENV_CONF_STR("UA_ENV_IAS_SPID", kUaConfIasSpid, "");
}

/// The C++ API for unified attestation authentication report generation
TeeErrorCode UaGenerateReport(UaReportGenerationParameters* param,
                              kubetee::UnifiedAttestationReport* report) {
  param->others.set_hex_spid(GetSpid());

  kubetee::attestation::AttestationGenerator generator;
  TEE_CHECK_RETURN(generator.Initialize(param->tee_identity));
  TEE_CHECK_RETURN(generator.GenerateReport(*param, report));

  return TEE_SUCCESS;
}

TeeErrorCode UaGenerateReportJson(UaReportGenerationParameters* param,
                                  std::string* report_json) {
  kubetee::UnifiedAttestationReport report;
  TEE_CHECK_RETURN(UaGenerateReport(param, &report));
  PB2JSON(report, report_json);
  TEE_LOG_DEBUG("UA Attestation Report type: %s", param->report_type.c_str());
  TEE_LOG_DEBUG("UA Attestation Report size: %ld", report_json->size());
  TEE_LOG_TRACE("UA Attestation Report: %s", report_json->c_str());
  return TEE_SUCCESS;
}

TeeErrorCode UaGenerateAuthReport(UaReportGenerationParameters* param,
                                  kubetee::UnifiedAttestationAuthReport* auth) {
  // Update the SPID it it's empty
  // Maybe still empty in configuration file or environment variable
  if (param->others.hex_spid().empty()) {
    param->others.set_hex_spid(GetSpid());
  }

  kubetee::UnifiedAttestationReport* report = auth->mutable_report();
  kubetee::attestation::AttestationGenerator generator;
  TEE_CHECK_RETURN(generator.Initialize(param->tee_identity));
  TEE_CHECK_RETURN(generator.GenerateReport(*param, report));

  std::string* p_public_key = auth->mutable_pem_public_key();
  const std::string& param_public_key = param->others.pem_public_key();
  if (param_public_key.empty()) {
    TEE_CHECK_RETURN(kubetee::attestation::ReeInstance::TeePublicKey(
        param->tee_identity, p_public_key));
  } else {
    p_public_key->assign(param_public_key);
  }
  TEE_LOG_TRACE("AuthReport Public Key:\n%s", p_public_key->c_str());

  TEE_LOG_DEBUG("Nested report: %s",
                param->others.json_nested_reports().c_str());
  auth->mutable_report()->set_json_nested_reports(
      param->others.json_nested_reports());

  return TEE_SUCCESS;
}

TeeErrorCode UaGenerateAuthReportJson(UaReportGenerationParameters* param,
                                      std::string* json_auth_report) {
  kubetee::UnifiedAttestationAuthReport auth;
  TEE_CHECK_RETURN(UaGenerateAuthReport(param, &auth));
  PB2JSON(auth, json_auth_report);
  TEE_LOG_DEBUG("Auth Report type: %s", param->report_type.c_str());
  TEE_LOG_DEBUG("Auth Report size: %ld", json_auth_report->size());
  TEE_LOG_TRACE("Auth Report: %s", json_auth_report->c_str());
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
