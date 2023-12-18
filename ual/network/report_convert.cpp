#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "network/report_convert.h"
#include "network/uas_client.h"

namespace kubetee {
namespace attestation {

TeeErrorCode ReportConvert::SgxDcapBgcheckToPassPortReport(
    kubetee::UnifiedAttestationReport* report) {
  std::string* json_report = report->mutable_json_report();
  kubetee::DcapReport dcap_report;
  JSON2PB(*json_report, &dcap_report);
  if (dcap_report.b64_quote().empty()) {
    TEE_LOG_ERROR("dcap_report.b64_quote can not be null");
    return TEE_ERROR_CONVERT_INFO_EMPTY;
  }
  kubetee::common::DataBytes b64_qoute_bytes(dcap_report.b64_quote());
  std::string quote = b64_qoute_bytes.FromBase64().GetStr();
  kubetee::attestation::PccsClient pccs_client;
  kubetee::SgxQlQveCollateral collateral;
  TEE_CHECK_RETURN(pccs_client.GetSgxCollateral(quote, &collateral));
  TEE_LOG_DEBUG("Get collateral from pccs success");

  PB2JSON(collateral, dcap_report.mutable_json_collateral());
  PB2JSON(dcap_report, json_report);
  report->set_str_report_type(kUaReportTypePassport);
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::SgxEpidBgcheckToPassPortReport(
    kubetee::UnifiedAttestationReport* report) {
  kubetee::EpidReport sgx1_report;
  JSON2PB(report->json_report(), &sgx1_report);
  const std::string b64_quote = sgx1_report.b64_quote();
  if (b64_quote.empty()) {
    TEE_LOG_ERROR("Cannot find b64_quote in report");
    return TEE_ERROR_CONVERT_INFO_EMPTY;
  }

  kubetee::attestation::RaIasClient ias_client;
  kubetee::IasReport ias_report;
  TEE_CHECK_RETURN(ias_client.FetchReport(b64_quote, &ias_report));

  std::string ias_report_json;
  PB2JSON(ias_report, &ias_report_json);
  report->set_str_report_type(kUaReportTypePassport);
  report->set_json_report(ias_report_json);
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::HyperEnclaveBgcheckToPassPortReport(
    kubetee::UnifiedAttestationReport* report) {
  TEE_LOG_DEBUG("hyperenclave platform report convert, do nothing");
  report->set_str_report_type(kUaReportTypePassport);
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::CsvBgcheckToPassPortReport(
    kubetee::UnifiedAttestationReport* report) {
  // Get the chip id from report
  kubetee::HygonCsvReport csv_report;
  JSON2PB(report->json_report(), &csv_report);

  // For CSV, the external reference data is HSK and CEK
  // Get the HSK and CEK from Hygon KDS
  kubetee::HygonCsvCertChain csv_certs;
  RaHygonKdsClient hygon_kds_client;
  TEE_CHECK_RETURN(
      hygon_kds_client.GetCsvHskCek(csv_report.str_chip_id(), &csv_certs));
  PB2JSON(csv_certs, csv_report.mutable_json_cert_chain());

  report->set_str_report_type(kUaReportTypePassport);
  PB2JSON(csv_report, report->mutable_json_report());
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::TdxBgcheckToPassPortReport(
    kubetee::UnifiedAttestationReport* report) {
  std::string* json_report = report->mutable_json_report();
  kubetee::IntelTdxReport tdx_report;
  JSON2PB(*json_report, &tdx_report);
  if (tdx_report.b64_quote().empty()) {
    TEE_LOG_ERROR("tdx_report.b64_quote can not be null");
    return TEE_ERROR_CONVERT_INFO_EMPTY;
  }
  kubetee::common::DataBytes b64_qoute_bytes(tdx_report.b64_quote());
  std::string quote = b64_qoute_bytes.FromBase64().GetStr();
  kubetee::attestation::PccsClient pccs_client;
  kubetee::SgxQlQveCollateral collateral;
  TEE_CHECK_RETURN(pccs_client.GetTdxCollateral(quote, &collateral));
  TEE_LOG_DEBUG("Get collateral from pccs success");

  PB2JSON(collateral, tdx_report.mutable_json_collateral());
  PB2JSON(tdx_report, json_report);
  report->set_str_report_type(kUaReportTypePassport);
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::KunpengBgcheckToPassPortReport(
    kubetee::UnifiedAttestationReport* report) {
  TEE_LOG_DEBUG("Huawei Kunpeng platform report convert, do nothing");
  report->set_str_report_type(kUaReportTypePassport);
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::BgcheckToPassport(
    kubetee::UnifiedAttestationReport* report) {
  // Copy the orignal data from input_report
  std::string platform = report->str_tee_platform();
  std::string report_type = report->str_report_type();
  TEE_LOG_DEBUG("report type is [%s], tee platform is [%s]",
                report_type.c_str(), platform.c_str());

  if (report_type != kUaReportTypeBgcheck) {
    TEE_LOG_ERROR("Cannot convert %s type", report_type.c_str());
    return TEE_ERROR_CONVERT_REPORT_TYPE_UNSUPPORT;
  }

  if (platform == kUaPlatformSgxDcap) {
    TEE_CHECK_RETURN(SgxDcapBgcheckToPassPortReport(report));
  } else if (platform == kUaPlatformSgxEpid) {
    TEE_CHECK_RETURN(SgxEpidBgcheckToPassPortReport(report));
  } else if (platform == kUaPlatformHyperEnclave) {
    TEE_CHECK_RETURN(HyperEnclaveBgcheckToPassPortReport(report));
  } else if (platform == kUaPlatformCsv) {
    TEE_CHECK_RETURN(CsvBgcheckToPassPortReport(report));
  } else if (platform == kUaPlatformTdx) {
    TEE_CHECK_RETURN(TdxBgcheckToPassPortReport(report));
  } else if (platform == kUaPlatformKunpeng) {
    TEE_CHECK_RETURN(KunpengBgcheckToPassPortReport(report));
  } else {
    TEE_LOG_ERROR("TEE platform [%s] is not support", platform.c_str());
    return TEE_ERROR_CONVERT_REPORT_PLATFORM_UNSUPPORT;
  }
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::BgcheckToPassportJson(
    const std::string& input_report_json, std::string* prepared_report_json) {
  kubetee::UnifiedAttestationReport report;
  JSON2PB(input_report_json, &report);
  TEE_CHECK_RETURN(BgcheckToPassport(&report));
  PB2JSON(report, prepared_report_json);
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::BgcheckToPassportAuthJson(
    const std::string& input_report_json, std::string* prepared_report_json) {
  kubetee::UnifiedAttestationAuthReport auth_report;
  JSON2PB(input_report_json, &auth_report);
  kubetee::UnifiedAttestationReport* report = auth_report.mutable_report();
  TEE_CHECK_RETURN(BgcheckToPassport(report));
  PB2JSON(auth_report, prepared_report_json);
  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::ConvertToUasReport(
    const kubetee::UnifiedAttestationReport& input_report,
    kubetee::UnifiedAttestationReport* uas_report) {
  kubetee::attestation::UasClient uas_client;
  std::string input_report_json;
  PB2JSON(input_report, &input_report_json);
  std::string uas_report_json;
  TEE_CHECK_RETURN(
      uas_client.GetUasReport(input_report_json, &uas_report_json));
  JSON2PB(uas_report_json, uas_report);

  return TEE_SUCCESS;
}

TeeErrorCode ReportConvert::ConvertToUasReportJson(
    const std::string& input_report_json, std::string* uas_report_json) {
  kubetee::attestation::UasClient uas_client;
  TEE_CHECK_RETURN(uas_client.GetUasReport(input_report_json, uas_report_json));

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
