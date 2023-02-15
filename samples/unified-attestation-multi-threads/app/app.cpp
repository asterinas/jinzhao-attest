#include <pthread.h>

#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "app/app.h"

using kubetee::attestation::ReeInstance;

static std::string g_tee_identity;

static int UntrustedAuthReportGeneration(const char* thread_name_str,
                                         std::string* json_auth_report) {
  const char* report_type = kUaReportTypePassport;
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  std::string thread_name = SAFESTR(thread_name_str);
  const std::string& report_identity = thread_name;

  do {
    // Call the TeeInstanceUpdateReportData() in enclave side
    // So, the untrusted user_data here will be ignored.
    kubetee::UnifiedFunctionGenericRequest req;
    kubetee::UnifiedFunctionGenericResponse res;
    req.add_argv(thread_name);
    ret = ReeInstance::TeeRun(g_tee_identity, "MultiThreadsReportInit", req,
                              &res);
    if (ret != 0) {
      printf("Fail to initialize report data: 0x%X\n", ret);
      break;
    }

    // Generate the unified attestation report
    UaReportGenerationParameters report_param;
    report_param.tee_identity = g_tee_identity;
    report_param.report_type = report_type;
    report_param.others.set_str_report_identity(report_identity);
    ret = UaGenerateAuthReportJson(&report_param, json_auth_report);
    if (ret != 0) {
      printf("Fail to generate authentication report: 0x%X\n", ret);
      break;
    }
  } while (0);

  return ret;
}

static int UntrustedAuthReportVerification(const char* thread_name_str,
                                           const std::string& auth_json) {
  kubetee::UnifiedAttestationPolicy policy;
  kubetee::UnifiedAttestationAttributes* attr = policy.add_main_attributes();
  attr->set_hex_ta_measurement("");
  attr->set_hex_signer("");
  attr->set_hex_prod_id("");
  attr->set_str_min_isvsvn("");
  attr->set_bool_debug_disabled("");
  attr->set_str_tee_platform("");
  // Must use the same value as what in generation sample code
  std::string thread_name = SAFESTR(thread_name_str);
  kubetee::common::DataBytes hex_report_data(thread_name);
  TEE_CHECK_RETURN(hex_report_data.ToHexStr().GetError());
  attr->set_hex_user_data(hex_report_data.GetStr());
  printf("%s user data: %s\n", thread_name.c_str(),
         attr->hex_user_data().c_str());
  std::string policy_json;
  PB2JSON(policy, &policy_json);

  int ret = UaVerifyAuthReportJson(auth_json, policy_json);
  if (ret) {
    printf("Fail to verify report ret = %x!!!\n", ret);
    return ret;
  }

  printf("Verify report successfully!\n");
  return 0;
}

void* pthread_handler_function(void* params) {
  const char* thread_name = RCAST(char*, params);
  printf("Start the thread: %s\n", thread_name);

  int ret = -1;
  do {
    std::string auth_json;
    if ((ret = UntrustedAuthReportGeneration(thread_name, &auth_json))) {
      printf("[%s] Fail to generate authentication report\n", thread_name);
      break;
    } else {
      printf("[%s] Generate auth report successfully!\n", thread_name);
    }
    if ((ret = UntrustedAuthReportVerification(thread_name, auth_json))) {
      printf("[%s] Fail to verify authentication report\n", thread_name);
      break;
    } else {
      printf("[%s] Verify auth report successfully!\n", thread_name);
    }
  } while (0);

  // return RCAST(void*, nullptr);
  return 0;
}

int SGX_CDECL main(void) {
  constexpr int kThreadNum = 10;
  pthread_t thread[kThreadNum];
  std::string thread_name[kThreadNum];

  kubetee::attestation::UaTeeInitParameters param;
  param.trust_application = ENCLAVE;
  TEE_CHECK_RETURN(ReeInstance::Initialize(param, &g_tee_identity));

  for (int i = 0; i < kThreadNum; i++) {
    thread_name[i] = "Thread" + std::to_string(i) + "\0";
    void* name = RCCAST(void*, thread_name[i].c_str());
    if (pthread_create(&thread[i], NULL, pthread_handler_function, name)) {
      printf("Fail to start %s\n", thread_name[i].c_str());
    }
  }

  for (int i = 0; i < kThreadNum; i++) {
    pthread_join(thread[i], NULL);
  }

  TEE_CHECK_RETURN(ReeInstance::Finalize(g_tee_identity));
  return 0;
}
