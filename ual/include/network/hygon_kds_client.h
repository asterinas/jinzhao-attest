#ifndef UAL_INCLUDE_NETWORK_HYGON_KDS_CLIENT_H_
#define UAL_INCLUDE_NETWORK_KYGON_KDS_CLIENT_H_

#include <map>
#include <memory>
#include <string>

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace attestation {

// Intel Attestation Server client for SGX EPID remote attestation mode
class RaHygonKdsClient {
 public:
  RaHygonKdsClient();
  ~RaHygonKdsClient();

  TeeErrorCode GetCsvHskCek(const std::string& chip_id,
                            kubetee::HygonCsvCertChain* hsk_cek);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_NETWORK_KYGON_KDS_CLIENT_H_
