#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <regex>
#include <string>
#include <utility>

#include "network/curl_http_client.h"

typedef struct {
  std::string http_response_data;
} HttpResponseData;

static size_t write_callback(void* ptr,
                             size_t size,
                             size_t nmemb,
                             void* stream) {
  HttpResponseData* res_data = RCAST(HttpResponseData*, stream);
  const char* contents = RCAST(char*, ptr);
  size_t content_length = size * nmemb;

  // the reponse maybe will be split into multi packages
  // and this function will be called more than once.
  res_data->http_response_data.append(contents, content_length);
  return content_length;
}

namespace kubetee {
namespace attestation {

// Define the static members
std::mutex CurlHttpClient::init_mutex_;

CurlHttpClient::CurlHttpClient() {
  // curl_global_init is not multithreads safe function. It's suggested to
  // call it in main thread. Here we just add lock to make sure safety, but
  // don't consider the performance, as multithreads is not common usecase.
  {
    std::lock_guard<std::mutex> lock(init_mutex_);
    curl_global_init(CURL_GLOBAL_ALL);
  }

  curl_ = curl_easy_init();
  if (!curl_) {
    return;
  }

#if !defined(NOLOG) && defined(DEBUGLOG)
  // Set libcurl verbose
  curl_easy_setopt(curl_, CURLOPT_VERBOSE, 1L);
#endif

  // Set commom option
  curl_easy_setopt(curl_, CURLOPT_FORBID_REUSE, 1L);
  curl_easy_setopt(curl_, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);
}

CurlHttpClient::~CurlHttpClient() {
  if (curl_) {
    curl_easy_cleanup(curl_);
  }
  // Add lock for multi-threads safety
  {
    std::lock_guard<std::mutex> lock(init_mutex_);
    curl_global_cleanup();
  }
}

TeeErrorCode CurlHttpClient::Unescape(const std::string& src,
                                      std::string* dst) {
  if (src.empty()) {
    TEE_LOG_ERROR("Empty string to be unescaped");
    return TEE_ERROR_CURL_RES_UNESCAPE_EMPTY;
  }
  int unescape_len = 0;
  char* unescape =
      curl_easy_unescape(curl_, src.data(), src.length(), &unescape_len);
  if (!unescape) {
    TEE_LOG_ERROR("Fail to unescape the string");
    return TEE_ERROR_CURL_RES_UNESCAPE_FAIL;
  }
  dst->assign(unescape, unescape_len);
  curl_free(unescape);
  return TEE_SUCCESS;
}

TeeErrorCode CurlHttpClient::HttpGet(const std::string& url,
                                     struct curl_slist* headerlist,
                                     std::string* body,
                                     std::string* header) {
  return DoHttpRequst(url, headerlist, body, header);
}

TeeErrorCode CurlHttpClient::HttpPost(const std::string& url,
                                      struct curl_slist* headerlist,
                                      const std::string& request_body,
                                      std::string* body,
                                      std::string* header) {
  headerlist = curl_slist_append(headerlist, "Content-Type:application/json");
  curl_easy_setopt(curl_, CURLOPT_POST, 1);
  curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, request_body.c_str());
  TEE_LOG_DEBUG("http request body: %s", request_body.c_str());
  return DoHttpRequst(url, headerlist, body, header);
}

TeeErrorCode CurlHttpClient::DoHttpRequst(const std::string& url,
                                          struct curl_slist* headerlist,
                                          std::string* response_body,
                                          std::string* response_header) {
  TEE_LOG_DEBUG("HttpRequest URL:[%s]", url.c_str());

  // Set the request url
  curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

  // set headers
  if (headerlist != nullptr) {
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headerlist);
  }

  // set callback data
  HttpResponseData http_response_body;
  HttpResponseData http_response_header;
  curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl_, CURLOPT_WRITEDATA, RCAST(void*, &http_response_body));
  curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, write_callback);
  curl_easy_setopt(curl_, CURLOPT_HEADERDATA,
                   RCAST(void*, &http_response_header));

  // Perform request
  CURLcode rc = curl_easy_perform(curl_);
  if (rc != CURLE_OK) {
    TEE_LOG_ERROR("Fail to connect server: %s", curl_easy_strerror(rc));
    return TEE_ERROR_CURL_GET_REQUEST;
  }
  int64_t status_code = 0;
  curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &status_code);
  if (status_code != 200) {
    TeeErrorCode ret = HttpServerStatus(status_code);
    TEE_LOG_ERROR("HttpServer connection status: 0x%x", ret);
    return ret;
  }

  // Copy and return the response
  response_body->assign(http_response_body.http_response_data);
  response_header->assign(http_response_header.http_response_data);
  return TEE_SUCCESS;
}

TeeErrorCode CurlHttpClient::HttpServerStatus(int64_t status_code) {
  switch (status_code) {
    case 200:
      return TEE_SUCCESS;
    case 403:
      return TEE_ERROR_CURL_NETWORK_ERROR;
    case 404:
      return TEE_ERROR_CURL_NO_CACHE_DATA;
    case 461:
      return TEE_ERROR_CURL_PLATFORM_UNKNOWN;
    case 462:
      return TEE_ERROR_CURL_CERTS_UNAVAILABLE;
    default:
      return TEE_ERROR_CURL_UNEXPECTED;
  }
}

TeeErrorCode CurlHttpClient::HttpHeader2Map(const std::string& header,
                                            HttpHeaderMap* header_map) {
  const char* ptr = header.data();
  size_t length = header.size();
  size_t start = 0;
  size_t end = 0;

  while (end < length) {
    // get the end of one line
    while (ptr[end] != '\r' && ptr[end] != '\n') {
      end++;
    }

    if (end == start) {
      // jump over the /r/n
      start++;
      end++;
    } else {
      // parse one line
      std::string header_line(ptr + start, end - start);
      size_t pos = header_line.find(": ");
      if (pos != std::string::npos) {
        // headers are case-insensitive. Convert to lower case for convenience.
        std::string name = header_line.substr(0, pos);
        std::string value = header_line.substr(pos + 2);
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        header_map->insert(std::pair<std::string, std::string>(name, value));
        TEE_LOG_TRACE("HEADER: %s=%s", name.c_str(), value.c_str());
      }
      start = end;
    }
  }
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
