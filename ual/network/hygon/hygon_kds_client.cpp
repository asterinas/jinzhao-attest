#include <unistd.h>

#include <map>
#include <string>

#include "attestation/common/log.h"
#include "attestation/platforms/csv.h"

#include "network/curl_http_client.h"
#include "network/hygon_kds_client.h"

namespace kubetee {
namespace attestation {

RaHygonKdsClient::RaHygonKdsClient() {}

RaHygonKdsClient::~RaHygonKdsClient() {}

TeeErrorCode RaHygonKdsClient::GetCsvHskCek(
    const std::string& chip_id, kubetee::HygonCsvCertChain* hsk_cek) {
  // Set the URL
  std::string url = "https://cert.hygon.cn/hsk_cek?snumber=";
  url += chip_id;

  // Set the sigrl request header and body handler function and data
  kubetee::attestation::CurlHttpClient curl_http_client;
  std::string response_body;
  std::string response_header;
  TEE_LOG_DEBUG("Hygon ChipID is [%s]", chip_id.c_str());
  TEE_CHECK_RETURN(
      curl_http_client.HttpGet(url, NULL, &response_body, &response_header));

  // Check the expected size
  const size_t cert_size = HYGON_HSK_CEK_CERT_SIZE;
  if (response_body.size() != HYGON_HSK_CEK_CERT_SIZE) {
    TEE_LOG_ERROR("Invalid HSK-CEK size: %ld bytes", response_body.size());
    return TEE_ERROR_HYGON_KDS_INVALID_CERT_SIZE;
  }
  if (sizeof(hygon_root_cert_t) != HYGON_CERT_SIZE) {
    TEE_LOG_ERROR("Invalid HSK struct size: %ld", sizeof(hygon_root_cert_t));
    return TEE_ERROR_HYGON_KDS_INVALID_HSK_SIZE;
  }
  if (sizeof(csv_cert_t) != HYGON_CSV_CERT_SIZE) {
    TEE_LOG_ERROR("Invalid CEK struct size: %ld", sizeof(csv_cert_t));
    return TEE_ERROR_HYGON_KDS_INVALID_CEK_SIZE;
  }
  csv_hsk_cek* pcert = RCCAST(csv_hsk_cek*, response_body.data());

  // Convert the hsk-cek string to protobuf message
  kubetee::common::DataBytes hsk(RCAST(uint8_t*, &(pcert->hsk)),
                                 sizeof(hygon_root_cert_t));
  kubetee::common::DataBytes cek(RCAST(uint8_t*, &(pcert->cek)),
                                 sizeof(csv_cert_t));
  hsk_cek->set_b64_hsk_cert(hsk.ToBase64().GetStr());
  hsk_cek->set_b64_cek_cert(cek.ToBase64().GetStr());
  TEE_LOG_DEBUG("HSK: %s", hsk.data());
  TEE_LOG_DEBUG("CEK: %s", cek.data());

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
