#ifndef UAL_INCLUDE_NETWORK_UAS_CLIENT_H_
#define UAL_INCLUDE_NETWORK_UAS_CLIENT_H_

#include <map>
#include <memory>
#include <string>

// Header files in include/sgx
#include "sgx/sgx_quote.h"
#include "sgx/sgx_uae_epid.h"
#include "sgx/sgx_urts.h"
#include "sgx/sgx_utils.h"

#include "curl/curl.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"

namespace kubetee {
namespace attestation {

// Intel Attestation Server client for SGX EPID remote attestation mode
class UasClient {
 public:
  UasClient();
  TeeErrorCode GetUasReport(const std::string& attestation_report_str,
                            std::string* uas_report_str);

 private:
  std::string GetUasUrl();
  TeeErrorCode GetBizId(std::string* biz_id);
  TeeErrorCode GetAppKeyAndAppSecret(std::string* app_key,
                                     std::string* app_secret);
  std::string uas_server_url_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_NETWORK_UAS_CLIENT_H_
