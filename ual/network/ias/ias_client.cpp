#include <unistd.h>

#include <map>
#include <string>

#include "rapidjson/document.h"

#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"

#include "network/curl_http_client.h"
#include "network/ias_client.h"
#include "utils/untrusted/untrusted_ua_config.h"

namespace kubetee {
namespace attestation {

constexpr char kStrHeaderSig[] = "x-iasreport-signature";
constexpr char kStrHeaderSigAk[] = "X-IASReport-Signature";
constexpr char kStrHeaderCa[] = "x-iasreport-signing-certificate";
constexpr char kStrHeaderCaAk[] = "X-IASReport-Signing-Certificate";
constexpr char kStrHeaderAdvisoryURL[] = "advisory-url";
constexpr char kStrHeaderAdvisoryIDs[] = "advisory-ids";

typedef struct {
  std::string b64_sigrl;
} IasSigrl;

std::string RaIasClient::GetIasUrl() {
  std::string url = "https://api.trustedservices.intel.com/sgx/attestation/v4";
  return UA_ENV_CONF_STR("UA_ENV_IAS_URL", kUaConfIasUrl, url);
}

RaIasClient::RaIasClient() {
  // curl_global_init is not multi threads safe function. It's suggested to
  // call it in main thread. Here we just add lock to make sure safety, but
  // don't consider the performance, as multi threads is not common use case.
  headers_ = curl_slist_append(NULL, "Accept: application/json");
  std::string header_access_key = "Ocp-Apim-Subscription-Key: ";
  std::string ias_api_key =
      UA_ENV_CONF_STR("UA_ENV_IAS_API_KEY", kUaConfIasApiKey, "");
  if (!ias_api_key.empty()) {
    header_access_key += ias_api_key;
    headers_ = curl_slist_append(headers_, header_access_key.c_str());
  }
}

RaIasClient::~RaIasClient() {
  if (headers_) {
    curl_slist_free_all(headers_);
  }
}

TeeErrorCode RaIasClient::GetSigRL(const sgx_epid_group_id_t* gid,
                                   std::string* sigrl) {
  // Set the URL
  kubetee::common::DataBytes gid_hex(RCAST(const uint8_t*, gid),
                                     sizeof(sgx_epid_group_id_t));
  std::string url = GetIasUrl() + "/sigrl/" + gid_hex.ToHexStr(true).GetStr();
  // Set the sigrl request header and body handler function and data
  kubetee::attestation::CurlHttpClient curl_http_client;
  std::string response_body;
  std::string response_header;
  TEE_CHECK_RETURN(curl_http_client.HttpGet(url, headers_, &response_body,
                                            &response_header));
  TEE_LOG_DEBUG("The IAS SigRL is [%s]", response_body.c_str());
  sigrl->assign(response_body);
  return TEE_SUCCESS;
}

TeeErrorCode RaIasClient::FetchReport(const std::string& b64_quote,
                                      kubetee::IasReport* ias_report) {
  // should not be empty is not to use cache
  if (b64_quote.empty()) {
    TEE_LOG_ERROR("Invalid base64 quote value");
    return TEE_ERROR_PARAMETERS;
  }

  // Set the report url
  std::string url = GetIasUrl() + "/report";

  // Set the post data
  std::string post_data = "{\"isvEnclaveQuote\": \"";
  post_data += b64_quote;
  post_data += "\"}";

  kubetee::attestation::CurlHttpClient curl_http_client;
  std::string response_body;
  std::string response_header;
  TEE_CHECK_RETURN(curl_http_client.HttpPost(url, headers_, post_data,
                                             &response_body, &response_header));
  HttpHeaderMap header_map;
  TEE_CHECK_RETURN(
      curl_http_client.HttpHeader2Map(response_header, &header_map));

  // set header info into ias_report
  std::map<std::string, std::string>::iterator it;
  for (it = header_map.begin(); it != header_map.end(); ++it) {
    if (it->first == kStrHeaderSig || it->first == kStrHeaderSigAk) {
      ias_report->set_b64_signature(it->second);
    } else if (it->first == kStrHeaderCa || it->first == kStrHeaderCaAk) {
      ias_report->set_str_signing_cert(it->second);
    } else if (it->first == kStrHeaderAdvisoryURL) {
      ias_report->set_str_advisory_url(it->second);
    } else if (it->first == kStrHeaderAdvisoryIDs) {
      ias_report->set_str_advisory_ids(it->second);
    }
  }

  // set response body into ias_report
  ias_report->set_json_response_body(response_body);

  // deal with the escaped certificates
  std::string unescape_unsigning_cert;
  TEE_CHECK_RETURN(curl_http_client.Unescape(ias_report->str_signing_cert(),
                                             &unescape_unsigning_cert));
  ias_report->set_str_signing_cert(unescape_unsigning_cert);
  TEE_LOG_INFO("Get IAS report successfully");

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
