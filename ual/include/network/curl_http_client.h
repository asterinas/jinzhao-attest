#ifndef UAL_INCLUDE_NETWORK_CURL_HTTP_CLIENT_H_
#define UAL_INCLUDE_NETWORK_CURL_HTTP_CLIENT_H_

#include <map>
#include <memory>
#include <string>

#include "curl/curl.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

#include "./pccs.pb.h"

typedef std::map<std::string, std::string> HttpHeaderMap;

namespace kubetee {
namespace attestation {

// PCCS client for SGX DCAP remote attestation mode
class CurlHttpClient {
 public:
  CurlHttpClient();
  ~CurlHttpClient();

  static std::mutex init_mutex_;
  CURL* curl_ = NULL;

  TeeErrorCode Unescape(const std::string& src, std::string* dst);

  TeeErrorCode HttpGet(const std::string& api,
                       struct curl_slist* headerlist,
                       std::string* body,
                       std::string* header);

  TeeErrorCode HttpPost(const std::string& url,
                        struct curl_slist* headerlist,
                        const std::string& request_body,
                        std::string* body,
                        std::string* header);

  TeeErrorCode HttpHeader2Map(const std::string& header,
                              HttpHeaderMap* header_map);

 private:
  TeeErrorCode DoHttpRequst(const std::string& url,
                            struct curl_slist* headerlist,
                            std::string* response_body,
                            std::string* response_header);

  TeeErrorCode HttpServerStatus(int64_t status_code);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_NETWORK_CURL_HTTP_CLIENT_H_
