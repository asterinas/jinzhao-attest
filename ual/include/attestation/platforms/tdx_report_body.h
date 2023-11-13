#ifndef UAL_INCLUDE_ATTESTATION_PLATFORMS_TDX_REPORT_BODY_H_
#define UAL_INCLUDE_ATTESTATION_PLATFORMS_TDX_REPORT_BODY_H_

#include <string>
#include <vector>

#include "./sgx_quote_4.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"

namespace kubetee {
namespace common {
namespace platforms {

class TdxReportBodyParser {
 public:
  // Quote/report_body level functions when parse report
  TeeErrorCode ParseReportBody(
      const std::string& quote,
      kubetee::UnifiedAttestationAttributes* attester_attr);

 private:
  std::string GetMrHex(const tee_measurement_t* mr);
  TeeErrorCode ParseReportBodyPfMeasurements(
      sgx_report2_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyBootMeasurements(
      sgx_report2_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyTaMeasurements(
      sgx_report2_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyAttributes(
      sgx_report2_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyUserData(
      sgx_report2_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportData(const uint8_t* report_data_buf,
                               const size_t report_data_len,
                               std::string* export_user_data,
                               std::string* export_pubkey_hash);
};

}  // namespace platforms
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_PLATFORMS_TDX_REPORT_BODY_H_
