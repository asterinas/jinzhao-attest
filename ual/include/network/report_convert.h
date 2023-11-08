#ifndef UAL_INCLUDE_NETWORK_REPORT_CONVERT_H_
#define UAL_INCLUDE_NETWORK_REPORT_CONVERT_H_

#include <string>

#include "attestation/common/attestation.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace attestation {

class ReportConvert {
 public:
  static TeeErrorCode BgcheckToPassport(
      kubetee::UnifiedAttestationReport* report);
  static TeeErrorCode BgcheckToPassportJson(
      const std::string& input_report_json, std::string* prepared_report_json);
  static TeeErrorCode BgcheckToPassportAuthJson(
      const std::string& input_report_json, std::string* prepared_report_json);
  static TeeErrorCode ConvertToUasReport(
      const kubetee::UnifiedAttestationReport& input_report,
      kubetee::UnifiedAttestationReport* uas_report);
  static TeeErrorCode ConvertToUasReportJson(
      const std::string& input_report_json, std::string* uas_report_json);

 private:
  static TeeErrorCode SgxDcapBgcheckToPassPortReport(
      kubetee::UnifiedAttestationReport* report);
  static TeeErrorCode SgxEpidBgcheckToPassPortReport(
      kubetee::UnifiedAttestationReport* report);
  static TeeErrorCode HyperEnclaveBgcheckToPassPortReport(
      kubetee::UnifiedAttestationReport* report);
  static TeeErrorCode CsvBgcheckToPassPortReport(
      kubetee::UnifiedAttestationReport* report);
  static TeeErrorCode TdxBgcheckToPassPortReport(
      kubetee::UnifiedAttestationReport* report);
  static TeeErrorCode KunpengBgcheckToPassPortReport(
      kubetee::UnifiedAttestationReport* report);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_NETWORK_REPORT_CONVERT_H_
