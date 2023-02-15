#ifndef UAL_INCLUDE_NETWORK_IAS_CLIENT_H_
#define UAL_INCLUDE_NETWORK_IAS_CLIENT_H_

#include <map>
#include <memory>
#include <string>

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
class RaIasClient {
 public:
  RaIasClient();
  ~RaIasClient();

  TeeErrorCode GetSigRL(const sgx_epid_group_id_t* gid, std::string* sigrl);
  TeeErrorCode FetchReport(const std::string& b64_quote,
                           kubetee::IasReport* ias_report);

 private:
  static std::string GetIasUrl();
  static std::string GetHeaderValue(const std::string& header);

  curl_slist* headers_ = NULL;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_NETWORK_IAS_CLIENT_H_
