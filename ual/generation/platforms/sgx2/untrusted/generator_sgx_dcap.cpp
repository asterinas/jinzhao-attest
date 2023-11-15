#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>  // for sleep()

#include <algorithm>
#include <string>

#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"
#include "attestation/platforms/sgx_report_body.h"
#include "attestation/verification/ua_verification.h"

#ifdef UA_ENV_TYPE_SGXSDK
#include "generation/platforms/sgx_common/untrusted/untrusted_sgx_common_ecall.h"
#else
#include "attestation/instance/trusted_tee_instance.h"
#endif

#include "generation/platforms/sgx2/untrusted/generator_sgx_dcap.h"
#include "generation/platforms/sgx_common/untrusted/untrusted_sgx_common.h"
#include "network/pccs_client.h"
#include "network/uas_client.h"
#include "utils/untrusted/untrusted_fs.h"
#include "utils/untrusted/untrusted_ua_config.h"

constexpr char kRhelLikeLibDir[] = "/usr/lib64/";
constexpr char kUbuntuLikeLibDir[] = "/usr/lib/x86_64-linux-gnu/";
constexpr char kPceLib[] = "libsgx_pce.signed.so";
constexpr char kQe3Lib[] = "libsgx_qe3.signed.so";
constexpr char kQplLib[] = "libdcap_quoteprov.so.1";

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationGeneratorSgxDcap::Initialize(
    const std::string& tee_identity) {
  if (tee_identity.empty()) {
    TEE_LOG_ERROR("Empty enclave identity");
    return TEE_ERROR_RA_NOTINITIALIZED;
  }
  try {
    enclave_id_ = std::stoll(tee_identity);
  } catch (std::exception& e) {
    TEE_LOG_ERROR("Invalid enclave identity");
    return TEE_ERROR_INVALID_ENCLAVE_ID;
  }
  if (enclave_id_ == 0) {
    return TEE_ERROR_INVALID_ENCLAVE_ID;
  }
  return TEE_SUCCESS;
}

#ifdef UA_ENV_TYPE_SGXSDK
TeeErrorCode AttestationGeneratorSgxDcap::LoadInProcQe() {
  // Following functions are valid in Linux in-proc mode only.
  // sgx_qe_set_enclave_load_policy is optional and the default
  // enclave load policy is persistent.
  TEE_LOG_DEBUG("Set the enclave load policy as persistent");
  quote3_error_t ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
  if (SGX_QL_SUCCESS != ret) {
    TEE_LOG_ERROR("Error in set enclave load policy: 0x%X", ret);
    return TEE_ERROR_MERGE(TEE_ERROR_RA_SET_ENCLAVE_LOAD_POLICY, ret);
  }

  // Set the PCE/QE3/QPL library path
  std::string default_lib_dir;
  if (kubetee::utils::FsFileExists("/usr/bin/apt-get")) {
    default_lib_dir.assign(kUbuntuLikeLibDir);
  } else {
    default_lib_dir.assign(kRhelLikeLibDir);
  }
  std::string lib_dir = UA_ENV_CONF_STR("UA_ENV_DCAP_LIB_PATH",
                                        kUaConfDcapLibPath, default_lib_dir);
  TEE_LOG_DEBUG("DCAP library path: %s", lib_dir.c_str());

  std::string pce_lib = lib_dir + kPceLib;
  std::string qe3_lib = lib_dir + kQe3Lib;
  std::string qpl_lib = lib_dir + kQplLib;
  TEE_LOG_DEBUG("pce_lib: %s", pce_lib.c_str());
  TEE_LOG_DEBUG("qe3_lib: %s", qe3_lib.c_str());
  TEE_LOG_DEBUG("qpl_lib: %s", qpl_lib.c_str());

  ret = sgx_ql_set_path(SGX_QL_PCE_PATH, pce_lib.c_str());
  if (SGX_QL_SUCCESS != ret) {
    TEE_LOG_ERROR("Fail to set PCE path, 0x%X", ret);
    return TEE_ERROR_MERGE(TEE_ERROR_RA_SET_QL_PATH, ret);
  }

  ret = sgx_ql_set_path(SGX_QL_QE3_PATH, qe3_lib.c_str());
  if (SGX_QL_SUCCESS != ret) {
    TEE_LOG_ERROR("Fail to set QE3 path, 0x%X", ret);
    return TEE_ERROR_MERGE(TEE_ERROR_RA_SET_QL_PATH, ret);
  }

  ret = sgx_ql_set_path(SGX_QL_QPL_PATH, qpl_lib.c_str());
  if (SGX_QL_SUCCESS != ret) {
    // Ignore the error, because user may want to get cert type=3 quote
    TEE_LOG_WARN("Cannot to set QPL path, 0x%X", ret);
    TEE_LOG_WARN("You may get ECDSA quote with `Encrypted PPID` cert type.");
  }

  return TEE_SUCCESS;
}

// Initialize the quote enclave and get the. gid for IAS sigRL
// and the target_info for sgx_create_report
TeeErrorCode AttestationGeneratorSgxDcap::InitTargetInfo() {
  quote3_error_t ret = sgx_qe_get_target_info(&target_info_);
  if (SGX_QL_SUCCESS != ret) {
    TEE_LOG_ERROR("Fail to get target info. 0x%0X", ret);
    return TEE_ERROR_MERGE(TEE_ERROR_RA_GET_TARGET_INFO, ret);
  }
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorSgxDcap::GetSgxReport(
    const UaReportGenerationParameters& param) {
  // Prepare report data
  sgx_report_data_t report_data;
  size_t len = sizeof(sgx_report_data_t);
  TEE_CHECK_RETURN(PrepareReportData(param, report_data.d, len));

  // Create the sgx report in enclave side
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  const char* report_identity = param.others.str_report_identity().c_str();
  const char* hex_spid = param.others.hex_spid().c_str();
  sgx_status_t rc =
      ecall_UaGenerateReport(enclave_id_, &ret, report_identity, hex_spid,
                             &target_info_, &report_data, &report_);
  if (TEE_ERROR_MERGE(ret, rc) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to do ecall_UaGenerateReport: 0x%X/0x%X", ret, rc);
    return TEE_ERROR_MERGE(ret, rc);
  }

  // save the attester attributes
  kubetee::common::platforms::SgxReportBodyParser report_body_parser;
  TEE_CHECK_RETURN(
      report_body_parser.ParseReportBody(&(report_.body), &attributes_));
  attributes_.set_hex_spid(hex_spid);

  TEE_LOG_DEBUG("Create SGX report successfully");
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorSgxDcap::GetSgxQuote(std::string* quote) {
  // Allocate the memory for quote
  uint32_t quote_size = 0;
  quote3_error_t ret = sgx_qe_get_quote_size(&quote_size);
  if (ret != SGX_QL_SUCCESS) {
    TEE_LOG_ERROR("Failed to call sgx_qe_get_quote_size: 0x%x", ret);
    return TEE_ERROR_MERGE(TEE_ERROR_RA_GET_QUOTE_SIZE, ret);
  }
  TEE_LOG_DEBUG("quote_size=%d", quote_size);

  // Ready to get quote now
  uint8_t* p_quote = SCAST(uint8_t*, malloc(quote_size));
  if (p_quote == nullptr) {
    TEE_LOG_ERROR("Fail to allocate the quote buffer");
    return TEE_ERROR_RA_MALLOC_QUOTE_BUFFER;
  }
  memset(p_quote, 0, quote_size);
  std::unique_ptr<uint8_t, void (*)(void*)> quote_ptr(p_quote, free);
  ret = sgx_qe_get_quote(&report_, quote_size, quote_ptr.get());
  if (ret != SGX_QL_SUCCESS) {
    TEE_LOG_ERROR("Fail to get enclave quote(): 0x%x", ret);
    return TEE_ERROR_MERGE(TEE_ERROR_RA_GET_QUOTE, ret);
  }
  TEE_LOG_BUFFER("QUOTE", quote_ptr.get(), quote_size);
  quote->assign(RCAST(char*, p_quote), SCAST(size_t, quote_size));
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorSgxDcap::GetQuote(
    const UaReportGenerationParameters& param, std::string* quote) {
  // There 2 modes on Linux:
  // One is in-proc mode, the QE3 and PCE are loaded within the user's process.
  // The other is out-of-proc mode, the QE3 and PCE are managed by a daemon.
  // The in-proc mode only need to install libsgx-dcap-ql.
  // The out-of-proc mode, you need to install libsgx-quote-ex as well.
  //
  // We only support in_proc_mode by default now.
  const bool in_proc_mode = true;
  if (in_proc_mode) {
    TEE_CHECK_RETURN(LoadInProcQe());
  }
  // Initialize quote enclave
  TEE_CHECK_RETURN(InitTargetInfo());

  // Get the sgx report from enclave side
  TEE_CHECK_RETURN(GetSgxReport(param));

  // Get the quote based on enclave internal public key and user data
  TEE_CHECK_RETURN(GetSgxQuote(quote));

  if (in_proc_mode) {
    // Clean up the enclave load policy for in-proc mode
    // But it does nothing in the sdk, so ignore it here
  }

  return TEE_SUCCESS;
}
#endif

#ifdef UA_ENV_TYPE_OCCLUM
// For Occlum LibOS environment
TeeErrorCode AttestationGeneratorSgxDcap::GetQuote(
    const UaReportGenerationParameters& param, std::string* quote) {
  // open the ioctl file
  int sgx_fd;
  if ((sgx_fd = open("/dev/sgx", O_RDONLY)) < 0) {
    ELOG_ERROR("Fail to open /dev/sgx");
    return TEE_ERROR_FILE_OPEN;
  }

  // get quote size
  uint32_t quote_size = 0;
  if (ioctl(sgx_fd, SGXIOC_GET_DCAP_QUOTE_SIZE, &quote_size) < 0) {
    ELOG_ERROR("Fail to get quote size");
    return TEE_ERROR_RA_GET_QUOTE_SIZE;
  }

  // prepare report data for getting quote
  sgx_report_data_t report_data = {0};
  size_t len = sizeof(sgx_report_data_t);
  TEE_CHECK_RETURN(PrepareReportData(param, report_data.d, len));
  // Replace the higher 32 bytes by HASH UAK public key
  if (param.others.pem_public_key().empty() && !UakPublic().empty()) {
    kubetee::common::DataBytes pubkey(UakPublic());
    pubkey.ToSHA256().Export(report_data.d + kSha256Size, kSha256Size).Void();
  }

  // prepare parameters for getting quote
  quote->resize(quote_size, 0);
  sgxioc_gen_dcap_quote_arg_t gen_quote_arg = {
      .report_data = &report_data,
      .quote_len = &quote_size,
      .quote_buf = RCCAST(uint8_t*, quote->data())};

  // get quote
  if (ioctl(sgx_fd, SGXIOC_GEN_DCAP_QUOTE, &gen_quote_arg) < 0) {
    ELOG_ERROR("Fail to get quote");
    return TEE_ERROR_RA_GET_QUOTE;
    quote->clear();
  }

  // Parse the attester attributes
  sgx_quote3_t* quote_ptr = RCCAST(sgx_quote3_t*, quote->data());
  kubetee::common::platforms::SgxReportBodyParser report_body_parser;
  TEE_CHECK_RETURN(report_body_parser.ParseReportBody(&(quote_ptr->report_body),
                                                      &attributes_));
  attributes_.set_hex_spid(param.others.hex_spid());

  return TEE_SUCCESS;
}
#endif

TeeErrorCode AttestationGeneratorSgxDcap::CreateBgcheckReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // Get the quote in binary but not base64 format
  // bebause PCCS need binary format
  std::string quote;
  TEE_CHECK_RETURN(GetQuote(param, &quote));

  // Convent quote to base64 format and prepare DcapReport
  kubetee::DcapReport dcap_report;
  kubetee::common::DataBytes quote_b64(quote);
  dcap_report.set_b64_quote(quote_b64.ToBase64().GetStr());

  // Make the final attestation report
  report->set_str_report_type(kUaReportTypeBgcheck);
  report->set_str_tee_platform(kUaPlatformSgxDcap);
  PB2JSON(dcap_report, report->mutable_json_report());

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorSgxDcap::CreatePassportReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // Get the quote in binary format
  std::string quote;
  TEE_CHECK_RETURN(GetQuote(param, &quote));

  // Get the quote verification collateral
  kubetee::SgxQlQveCollateral collateral;
  PccsClient pccs_client;
  TEE_CHECK_RETURN(pccs_client.GetSgxCollateral(quote, &collateral));

  // Convent quote to base64 format and prepare DcapReport
  kubetee::DcapReport dcap_report;
  kubetee::common::DataBytes quote_b64(quote);
  dcap_report.set_b64_quote(quote_b64.ToBase64().GetStr());
  TEE_LOG_TRACE("QUOTE BASE64[%lu]: %s", dcap_report.b64_quote().size(),
                dcap_report.b64_quote().c_str());
  PB2JSON(collateral, dcap_report.mutable_json_collateral());

  // Make the final attestation report
  report->set_str_tee_platform(kUaPlatformSgxDcap);
  report->set_str_report_type(kUaReportTypePassport);
  PB2JSON(dcap_report, report->mutable_json_report());

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
