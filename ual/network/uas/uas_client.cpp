#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <string>

#include "attestation/common/attestation.h"
#include "attestation/common/protobuf.h"
#include "network/curl_http_client.h"
#include "network/uas_client.h"

#include "utils/untrusted/untrusted_ua_config.h"

namespace kubetee {
namespace attestation {

UasClient::UasClient() {
  // Prepare the url
  uas_server_url_ = GetUasUrl();
}

std::string UasClient::GetUasUrl() {
  return UA_ENV_CONF_STR("UA_ENV_UAS_URL", kUaConfUasUrl, "");
}

TeeErrorCode UasClient::GetBizId(std::string* biz_id) {
  kubetee::common::DataBytes biz;
  biz.Randomize(16).Void();
  biz_id->assign(biz.ToHexStr().GetStr());
  return TEE_SUCCESS;
}

TeeErrorCode UasClient::GetAppKeyAndAppSecret(std::string* app_key,
                                              std::string* app_secret) {
  app_key->assign(UA_ENV_CONF_STR("UA_ENV_UAS_APP_KEY", kUaConfUasAppKey, ""));
  if (app_key->empty()) {
    TEE_LOG_ERROR("get app key from env error");
    return TEE_ERROR_UAS_GET_APP_KEY;
  }

  app_secret->assign(
      UA_ENV_CONF_STR("UA_ENV_UAS_APP_SECRET", kUaConfUasAppSecret, ""));
  if (app_secret->empty()) {
    TEE_LOG_ERROR("get app secret from env error");
    return TEE_ERROR_UAS_GET_APP_SECRET;
  }

  return TEE_SUCCESS;
}

TeeErrorCode UasClient::GetUasReport(const std::string& attestation_report_str,
                                     std::string* uas_report_str) {
  kubetee::UnifiedAttestationReport attestation_report;
  JSON2PB(attestation_report_str, &attestation_report);

  // set http request body
  kubetee::UasHttpRequest uas_http_request;
  std::string biz_id;
  TEE_CHECK_RETURN(GetBizId(&biz_id));
  uas_http_request.set_report(attestation_report_str);
  uas_http_request.set_biz_id(biz_id);
  std::string app_key;
  std::string app_secret;
  TEE_CHECK_RETURN(GetAppKeyAndAppSecret(&app_key, &app_secret));
  uas_http_request.set_app_key(app_key);
  uas_http_request.set_app_secret(app_secret);

  // send http request
  std::string uas_http_request_str;
  PB2JSON(uas_http_request, &uas_http_request_str);
  std::string response_data;
  std::string response_header;
  kubetee::attestation::CurlHttpClient curl_http_client;
  struct curl_slist* headerlist = NULL;
  TEE_CHECK_RETURN(curl_http_client.HttpPost(uas_server_url_, headerlist,
                                             uas_http_request_str,
                                             &response_data, &response_header));
  TEE_LOG_DEBUG("response_data: %s", response_data.c_str());

  // Check the java code result code
  kubetee::UasHttpResponse uas_http_response;
  JSON2PB(response_data.c_str(), &uas_http_response);
  if (uas_http_response.result_code() != TEE_SUCCESS) {
    TEE_LOG_ERROR("UAS java api error, result_msg: %s",
                  uas_http_response.result_msg().c_str());
    return TEE_ERROR_UAS_JAVA_ERROR;
  }

  // Check the UAL result code
  kubetee::UasReport uas_report;
  kubetee::UasAttestionResult uas_result;
  JSON2PB(uas_http_response.uas_report(), &uas_report);
  JSON2PB(uas_report.json_result(), &uas_result);
  if (uas_result.int64_result_code() != TEE_SUCCESS) {
    // Return the UAL error code in UAS if failed
    TEE_LOG_ERROR("UAS call UAL api failed, result code: 0x%lX",
                  uas_result.int64_result_code());
    return uas_result.int64_result_code();
  }

  // return the data with response body and signature
  uas_report_str->assign(uas_http_response.uas_report());
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
