#ifndef UAL_INCLUDE_ATTESTATION_PLATFORMS_SGX_REPORT_BODY_H_
#define UAL_INCLUDE_ATTESTATION_PLATFORMS_SGX_REPORT_BODY_H_

#include <string>
#include <vector>

#include "./sgx_quote.h"
#include "./sgx_report.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"

namespace kubetee {
namespace common {
namespace platforms {

class SgxReportBodyParser {
 public:
  // Quote/report_body level functions when parse report
  TeeErrorCode ParseReportBody(
      sgx_report_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);

 private:
  TeeErrorCode ParseReportBodyMRENCLAVE(
      sgx_report_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyMRSIGNER(
      sgx_report_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyAttributes(
      sgx_report_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyIsvProd(
      sgx_report_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyIsvSvn(
      sgx_report_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportBodyUserData(
      sgx_report_body_t* report_body,
      kubetee::UnifiedAttestationAttributes* attester_attr);
  TeeErrorCode ParseReportData(const uint8_t* report_data_buf,
                               const size_t report_data_len,
                               std::string* export_user_data,
                               std::string* export_pubkey_hash);
};

}  // namespace platforms
}  // namespace common
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_PLATFORMS_SGX_REPORT_BODY_H_
