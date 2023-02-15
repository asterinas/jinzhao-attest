#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "app/app.h"

const char kReportPrefix[] = "unified_attestation_auth_report_";

int convertToUasReport(const char* report_type) {
  std::string report_type_str(SAFESTR(report_type));
  std::string filename = kReportPrefix;
  filename.append(report_type_str + ".json");
  TEE_LOG_INFO("Origianl report: %s", filename.c_str());

  std::string auth_report_json;
  if (kubetee::utils::FsReadString(filename, &auth_report_json) != 0) {
    TEE_LOG_ERROR("Fail to load the report JSON file");
    return -1;
  }

  kubetee::UnifiedAttestationAuthReport auth_report;
  JSON2PB(auth_report_json, &auth_report);
  std::string report_json;
  PB2JSON(auth_report.report(), &report_json);
  std::string uas_report_json;
  kubetee::attestation::ReportConvert report_covert;
  int ret = report_covert.ConvertToUasReportJson(report_json, &uas_report_json);
  if (ret != 0) {
    TEE_LOG_ERROR("GetUasReport error, error_code = %x", ret);
    return ret;
  }

  std::string converted_filename = kReportPrefix;
  converted_filename.append(report_type_str + "_coverted_Uas.json");
  TEE_LOG_INFO("Converted report: %s", converted_filename.c_str());
  if (kubetee::utils::FsWriteString(converted_filename, uas_report_json) != 0) {
    TEE_LOG_ERROR("Failed write uas report into JSON file");
    return -1;
  }

  return 0;
}

int BgcheckToPassport(const char* report_type) {
  std::string report_type_str(SAFESTR(report_type));
  std::string filename = kReportPrefix;
  filename.append(report_type_str + ".json");
  TEE_LOG_INFO("Origianl report: %s", filename.c_str());

  std::string auth_report_json;
  if (kubetee::utils::FsReadString(filename, &auth_report_json) != 0) {
    TEE_LOG_ERROR("Fail to load the report JSON file");
    return -1;
  }

  kubetee::UnifiedAttestationAuthReport auth_report;
  JSON2PB(auth_report_json, &auth_report);
  std::string report_json;
  PB2JSON(auth_report.report(), &report_json);
  std::string converted_json;
  kubetee::attestation::ReportConvert covert;
  int ret = covert.BgcheckToPassportJson(report_json, &converted_json);
  if (ret != 0) {
    TEE_LOG_ERROR("GetUasReport error,  error_code = %x", ret);
    return ret;
  }

  std::string converted_filename = kReportPrefix;
  converted_filename.append(report_type_str + "_coverted_Passport.json");
  TEE_LOG_INFO("Converted report: %s", converted_filename.c_str());
  if (kubetee::utils::FsWriteString(converted_filename, converted_json) != 0) {
    TEE_LOG_ERROR("Failed write uas report into JSON file");
    return -1;
  }

  return 0;
}

// run app-sample-unified-attestation-generation generate report firstly
int main(void) {
  // TEE_CHECK_RETURN(convertToUasReport(kUaReportTypeUas));
  // TEE_CHECK_RETURN(convertToUasReport(kUaReportTypeBgcheck));
  // TEE_CHECK_RETURN(convertToUasReport(kUaReportTypePassport));
  TEE_CHECK_RETURN(BgcheckToPassport(kUaReportTypeBgcheck));

  printf("convert to report successfully\n");
  return 0;
}
