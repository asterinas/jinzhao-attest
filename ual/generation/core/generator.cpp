#include <memory>
#include <string>

#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/uak.h"
#include "attestation/generation/core/generator.h"
#include "utils/untrusted/untrusted_fs.h"

#include "network/report_convert.h"

#ifdef UA_TEE_TYPE_HYPERENCLAVE
#include "generation/platforms/hyperenclave/untrusted/generator_hyperenclave.h"
#endif
#ifdef UA_TEE_TYPE_SGX2
#include "generation/platforms/sgx2/untrusted/generator_sgx_dcap.h"
#endif
#ifdef UA_TEE_TYPE_SGX1
#include "generation/platforms/sgx1/untrusted/generator_sgx_epid.h"
#endif
#ifdef UA_TEE_TYPE_CSV
#include "generation/platforms/csv/generator_csv.h"
#endif
#ifdef UA_TEE_TYPE_TDX
#include "generation/platforms/tdx/generator_tdx.h"
#endif

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationGenerator::Initialize(const std::string& tee_identity) {
  using kubetee::utils::FsFileExists;

#ifdef SGX_MODE_SIM
  TEE_LOG_DEBUG("Process Running on SGX SIM environment");
#ifndef UA_TEE_TYPE_SGX1
  TEE_LOG_ERROR("SGX SIM MODE can only use UA_TEE_TYPE_SGX1");
  return TEE_ERROR_UNSUPPORTED_TEE;
#endif
#endif
  // Check the TEE device
  if (false) {
    // Just for if-else beginning
#ifdef UA_ENV_TYPE_OCCLUM
  } else if (FsFileExists("/dev/sgx")) {
    TEE_LOG_DEBUG("TEE device for Occlum LibOS");
#endif
#ifdef UA_TEE_TYPE_HYPERENCLAVE
  } else if (FsFileExists("/dev/jailhouse") ||
             FsFileExists("/dev/hyperenclave")) {
    TEE_LOG_DEBUG("TEE device for HyperEnclave platform");
#endif
#ifdef UA_TEE_TYPE_SGX2
  } else if (FsFileExists("/dev/sgx_enclave") ||
             FsFileExists("/dev/sgx/enclave")) {
    TEE_LOG_DEBUG("TEE device for SGX2 platform");
#endif
#ifdef UA_TEE_TYPE_SGX1
  } else if (FsFileExists("/dev/isgx")) {
    TEE_LOG_DEBUG("TEE device for SGX1 platform");
#endif
  } else {
#ifdef UA_TEE_TYPE_CSV
    TEE_LOG_DEBUG("Hygon CSV TEE platform");
#elif defined(UA_TEE_TYPE_TDX)
    TEE_LOG_DEBUG("Intel TDX TEE platform");
#else
#ifndef SGX_MODE_SIM
    TEE_LOG_ERROR("Unsupported trusted execution environment");
    return TEE_ERROR_UNSUPPORTED_TEE;
#endif
#endif
  }

#ifdef UA_TEE_TYPE_HYPERENCLAVE
  inner_ = std::make_shared<AttestationGeneratorHyperEnclave>();
#endif
#ifdef UA_TEE_TYPE_SGX2
  inner_ = std::make_shared<AttestationGeneratorSgxDcap>();
#endif
#ifdef UA_TEE_TYPE_SGX1
  inner_ = std::make_shared<AttestationGeneratorSgxEpid>();
#endif
#ifdef UA_TEE_TYPE_CSV
  inner_ = std::make_shared<AttestationGeneratorCsv>();
#endif
#ifdef UA_TEE_TYPE_TDX
  inner_ = std::make_shared<AttestationGeneratorTdx>();
#endif

  TEE_CHECK_RETURN(inner_->Initialize(tee_identity));
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGenerator::GenerateReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  const std::string& report_type = param.report_type;
  if (report_type == kUaReportTypeBgcheck) {
    TEE_CHECK_RETURN(inner_->CreateBgcheckReport(param, report));
  } else if (report_type == kUaReportTypePassport) {
    TEE_CHECK_RETURN(inner_->CreatePassportReport(param, report));
  } else if (report_type == kUaReportTypeUas) {
    kubetee::UnifiedAttestationReport bgc_report;
    TEE_CHECK_RETURN(inner_->CreateBgcheckReport(param, &bgc_report));
    TEE_CHECK_RETURN(ReportConvert::ConvertToUasReport(bgc_report, report));
  } else {
    TEE_LOG_ERROR("Unsupport report_type: %s", report_type.c_str());
    return TEE_ERROR_RA_REPORT_TYPE;
  }
  report->set_str_report_version(kCurrentUarVersion);
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGenerator::GetAttesterAttr(
    kubetee::UnifiedAttestationAttributes* attr) {
  TEE_CHECK_RETURN(inner_->GetAttesterAttr(attr));
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
