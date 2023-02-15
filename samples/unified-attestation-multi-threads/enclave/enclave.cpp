#include <string>

#include "unified_attestation/ua_trusted.h"

#include "enclave/enclave.h"

TeeErrorCode MultiThreadsReportInit(const std::string& req_str,
                                    std::string* res_str) {
  kubetee::UnifiedFunctionGenericRequest req;
  kubetee::UnifiedFunctionGenericResponse res;
  JSON2PB(req_str, &req);

  // The first argv saved thread_name
  // which is also used as the report_identity and report_data
  const std::string& thread_name = req.argv(0);
  const std::string& report_identity = thread_name;
  kubetee::common::DataBytes hex_report_data(thread_name);
  TEE_CHECK_RETURN(hex_report_data.ToHexStr().GetError());
  TEE_CHECK_RETURN(
      TeeInstanceUpdateReportData(hex_report_data.GetStr(), report_identity));

  // Add UAK public key as Response
  res.add_result(UakPublic());
  PB2JSON(res, res_str);

  ELOG_INFO("MultiThreadsReportInit successfully!");
  return 0;
}

TeeErrorCode RegisterTrustedUnifiedFunctionsEx() {
  ADD_TRUSTED_UNIFIED_FUNCTION(MultiThreadsReportInit);
  return TEE_SUCCESS;
}
