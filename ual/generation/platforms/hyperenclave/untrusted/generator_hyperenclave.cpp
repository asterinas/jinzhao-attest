#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>  // for sleep() function

#include <algorithm>
#include <string>
#include <vector>

#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/type.h"
#include "attestation/platforms/sgx_report_body.h"
#include "attestation/verification/ua_verification.h"

#ifdef UA_ENV_TYPE_SGXSDK
#include "generation/platforms/sgx_common/untrusted/untrusted_sgx_common_ecall.h"
#endif
#ifdef UA_ENV_TYPE_OCCLUM
#include "attestation/common/uak.h"
#include "attestation/instance/trusted_tee_instance.h"
#endif

#include "generation/platforms/hyperenclave/untrusted/generator_hyperenclave.h"
#include "generation/platforms/sgx_common/untrusted/untrusted_sgx_common.h"
#include "network/uas_client.h"

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationGeneratorHyperEnclave::Initialize(
    const std::string& tee_identity) {
  if (tee_identity.empty()) {
    TEE_LOG_ERROR("Enclave has not been created successfully");
    return TEE_ERROR_RA_NOTINITIALIZED;
  }
  try {
    enclave_id_ = std::stoll(tee_identity);
  } catch (std::exception& e) {
    return TEE_ERROR_INVALID_ENCLAVE_ID;
  }
  if (enclave_id_ == 0) {
    return TEE_ERROR_INVALID_ENCLAVE_ID;
  }
  return TEE_SUCCESS;
}

#ifdef UA_ENV_TYPE_SGXSDK
// Initialize the quote enclave and get the gid for IAS sigRL
// and the target_info for sgx_create_report
TeeErrorCode AttestationGeneratorHyperEnclave::InitTargetInfo() {
  TeeErrorCode ret = TEE_ERROR_SGX_ERROR_BUSY;
  int try_count = 5;
  while (try_count-- && (ret == TEE_ERROR_SGX_ERROR_BUSY)) {
    ret = SCAST(TeeErrorCode, sgx_init_quote(&target_info_, &gid_));
    TEE_LOG_INFO("Initialize quote [%d]: %d", try_count, ret);
    if (ret == SGX_SUCCESS) {
      break;
    } else {
      sleep(1);
    }
  }
  if (ret != SGX_SUCCESS) {
    TEE_LOG_ERROR("Failed to initialize quote enclave: 0x%x", ret);
    return ret;
  }

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorHyperEnclave::GetSgxReport(
    const UaReportGenerationParameters& param, sgx_report_t* p_report) {
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
                             &target_info_, &report_data, p_report);
  if (TEE_ERROR_MERGE(ret, rc) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to do ecall_UaGenerateReport: 0x%X/0x%X", ret, rc);
    return TEE_ERROR_MERGE(ret, rc);
  }

  // save the attester attributes
  kubetee::common::platforms::SgxReportBodyParser report_body_parser;
  TEE_CHECK_RETURN(
      report_body_parser.ParseReportBody(&(p_report->body), &attributes_));
  attributes_.set_hex_spid(hex_spid);

  TEE_LOG_INFO("Create enclave report successfully");
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorHyperEnclave::GetSgxQuote(
    const UaReportGenerationParameters& param, std::string* pquote_b64) {
  // Get the sgx report from enclave side
  sgx_report_t report;
  TEE_CHECK_RETURN(GetSgxReport(param, &report));

  // HyperEnclave don't support SigRL yet
  uint8_t* psigrl = NULL;
  uint32_t sigrl_len = 0;

  // Allocate the memory for quote
  uint32_t quote_size = 0;
  sgx_status_t rc = sgx_calc_quote_size(psigrl, sigrl_len, &quote_size);
  if (rc != SGX_SUCCESS) {
    TEE_LOG_ERROR("Failed to call sgx_calc_quote_size(): 0x%x", rc);
    return TEE_ERROR_CODE(rc);
  }
  TEE_LOG_DEBUG("quote_size=%d", quote_size);

  // Generate nonce
  sgx_quote_nonce_t nonce;
  kubetee::common::DataBytes random;
  random.Randomize(sizeof(sgx_quote_nonce_t))
      .Export(RCAST(uint8_t*, &nonce), sizeof(sgx_quote_nonce_t));
  TEE_LOG_BUFFER("REPORT NONCE", nonce.rand, sizeof(sgx_quote_nonce_t));

  // HyperEnclave don't need SPID, just use empty value
  sgx_spid_t sgx_spid;
  memset(sgx_spid.id, 0, sizeof(sgx_spid_t));

  // Ready to get quote now
  sgx_report_t qe_report;
  std::unique_ptr<sgx_quote_t, void (*)(void*)> quote_ptr(
      SCAST(sgx_quote_t*, malloc(quote_size)), free);
  const sgx_quote_sign_type_t quote_type = SGX_LINKABLE_SIGNATURE;
  rc = sgx_get_quote(&report, quote_type, &sgx_spid, &nonce, psigrl, sigrl_len,
                     &qe_report, quote_ptr.get(), quote_size);
  if (rc != SGX_SUCCESS) {
    TEE_LOG_ERROR("Fail to get enclave quote(): 0x%x", rc);
    return TEE_ERROR_CODE(rc);
  }
  // Verify the quote enclave report
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  rc = ecall_UaVerifyReport(enclave_id_, &ret, &target_info_, &qe_report);
  if ((TEE_ERROR_MERGE(ret, rc)) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to verify QE report: 0x%x/0x%x", ret, rc);
    return TEE_ERROR_MERGE(ret, rc);
  }
  TEE_LOG_BUFFER("QUOTE", quote_ptr.get(), quote_size);

  // Convert the quote data into base64 format
  kubetee::common::DataBytes quote(RCAST(uint8_t*, quote_ptr.get()),
                                   SCAST(size_t, quote_size));
  pquote_b64->assign(quote.ToBase64().GetStr());
  TEE_LOG_DEBUG("QUOTE BASE64[%lu]: %s", pquote_b64->length(),
                pquote_b64->c_str());
  return TEE_SUCCESS;
}
#endif

#ifdef UA_ENV_TYPE_OCCLUM
// For Occlum LibOS environment
TeeErrorCode AttestationGeneratorHyperEnclave::SgxDeviceGetGroupID() {
  // sgx_init_quote will be called in ioctl handler
  int sgx_fd;
  if ((sgx_fd = open(kSgxDeviceName, O_RDONLY)) < 0) {
    TEE_LOG_ERROR("Fail to open %s", kSgxDeviceName);
    return TEE_ERROR_RA_GENERATE_OCCLUM_FILE_OPEN;
  }

  TeeErrorCode ret = TEE_SUCCESS;
  if (ioctl(sgx_fd, SGXIOC_GET_EPID_GROUP_ID, &gid_) < 0) {
    TEE_LOG_ERROR("Fail to get group id from  %s", kSgxDeviceName);
    ret = TEE_ERROR_RA_GENERATE_OCCLUM_GET_GROUP_ID;
  }

  close(sgx_fd);
  return ret;
}

TeeErrorCode AttestationGeneratorHyperEnclave::SgxDeviceGetQuote(
    sgxioc_gen_epid_quote_arg_t* quote_args) {
  if (!quote_args->quote.as_buf || (quote_args->quote_buf_len == 0)) {
    TEE_LOG_ERROR("Invalid quote buffer or len");
    return TEE_ERROR_RA_GENERATE_OCCLUM_QUOTE_ARGS;
  }

  int sgx_fd;
  if ((sgx_fd = open(kSgxDeviceName, O_RDONLY)) < 0) {
    TEE_LOG_ERROR("Fail to open %s", kSgxDeviceName);
    return TEE_ERROR_RA_GENERATE_OCCLUM_FILE_OPEN;
  }

  TeeErrorCode ret = TEE_SUCCESS;
  int count = 3;
  while (count--) {
    if (ioctl(sgx_fd, SGXIOC_GEN_QUOTE, quote_args) == 0) {
      uint32_t signature_len = quote_args->quote.as_quote->signature_len;
      TEE_LOG_DEBUG("SgxDeviceGetQuote length=%ld", signature_len);
      if (signature_len == 0) {
        TEE_LOG_ERROR("Invalid quote from %s", kSgxDeviceName);
        ret = TEE_ERROR_RA_GENERATE_OCCLUM_QUOTE_LEN;
      }
      break;
    } else if (errno != EAGAIN) {
      TEE_LOG_ERROR("Fail to get quote from %s", kSgxDeviceName);
      ret = TEE_ERROR_RA_GENERATE_OCCLUM_DEVICE_BUSY;
      break;
    } else {
      TEE_LOG_WARN("Device is temporarily busy. Try again after 1s.");
      sleep(1);
    }
  }

  close(sgx_fd);
  return ret;
}

TeeErrorCode AttestationGeneratorHyperEnclave::InitTargetInfo() {
  return SgxDeviceGetGroupID();
}

TeeErrorCode AttestationGeneratorHyperEnclave::GetSgxQuote(
    const UaReportGenerationParameters& param, std::string* pquote_b64) {
  // Initialize the argmument structure
  sgxioc_gen_epid_quote_arg_t quote_args;
  memset(RCAST(void*, &quote_args), 0, sizeof(sgxioc_gen_epid_quote_arg_t));

  // Prepare quote_args.report_data
  // Use report_data from the parameter directly.
  sgx_report_data_t report_data = {0};
  size_t len = sizeof(sgx_report_data_t);
  TEE_CHECK_RETURN(PrepareReportData(param, report_data.d, len));
  // Replace the higher 32 bytes by HASH UAK public key
  if (param.others.pem_public_key().empty() && !UakPublic().empty()) {
    kubetee::common::DataBytes pubkey(UakPublic());
    pubkey.ToSHA256().Export(report_data.d + kSha256Size, kSha256Size).Void();
  }
  std::memcpy(RCAST(void*, quote_args.report_data.d),
              RCAST(const void*, report_data.d), sizeof(sgx_report_data_t));

  // Prepare quote_args.quote_type
  quote_args.quote_type = SGX_LINKABLE_SIGNATURE;

  // Prepare quote_args.spid
  // HyperEnclave don't need SPID, just use empty value
  memset(quote_args.spid.id, 0, sizeof(sgx_spid_t));

  // Prepare quote_args.nonce
  kubetee::common::DataBytes random;
  random.Randomize(sizeof(sgx_quote_nonce_t))
      .Export(RCAST(uint8_t*, quote_args.nonce.rand),
              sizeof(sgx_quote_nonce_t));

  // Prepare quote_args.sigrl_ptr and quote_args.sigrl_len
  // HyperEnclave don't support SigRL yet
  std::string sigrl_res;
  quote_args.sigrl_ptr = NULL;
  quote_args.sigrl_len = 0;

  // Prepare quote_args.quote and quote_args.quote_buf_len
  constexpr int kMaxQuoteLen = 4096;
  std::vector<uint8_t> quote_buf;
  quote_buf.resize(kMaxQuoteLen, 0);
  quote_args.quote.as_buf = quote_buf.data();
  quote_args.quote_buf_len = quote_buf.size();

  // Get quote via ioctl device
  TEE_CHECK_RETURN(SgxDeviceGetQuote(&quote_args));

  // Convert the quote data to base64 format
  size_t quote_signature_len = quote_args.quote.as_quote->signature_len;
  size_t quote_len = sizeof(sgx_quote_t) + quote_signature_len;
  kubetee::common::DataBytes quote(quote_args.quote.as_buf, quote_len);
  pquote_b64->assign(quote.ToBase64().GetStr());
  TEE_LOG_DEBUG("QuoteB64[%lu]: %s", pquote_b64->length(), pquote_b64->c_str());

  // Parse the attester attributes
  sgx_quote_t* pquote = quote_args.quote.as_quote;
  kubetee::common::platforms::SgxReportBodyParser report_body_parser;
  TEE_CHECK_RETURN(
      report_body_parser.ParseReportBody(&(pquote->report_body), &attributes_));
  attributes_.set_hex_spid(param.others.hex_spid());

  return TEE_SUCCESS;
}
#endif

TeeErrorCode AttestationGeneratorHyperEnclave::GetQuote(
    const UaReportGenerationParameters& param, std::string* pquote_b64) {
  // Initialize quote enclave for target info and gid
  TEE_CHECK_RETURN(InitTargetInfo());

  // Get the quote based on enclave internal public key and user data
  TEE_CHECK_RETURN(GetSgxQuote(param, pquote_b64));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorHyperEnclave::CreateBgcheckReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // Get attestation quote
  kubetee::HyperEnclaveReport hyper_report;
  TEE_CHECK_RETURN(GetQuote(param, hyper_report.mutable_b64_quote()));

  // Make the final report with quote only
  report->set_str_tee_platform(kUaPlatformHyperEnclave);
  report->set_str_report_type(kUaReportTypeBgcheck);
  PB2JSON(hyper_report, report->mutable_json_report());

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorHyperEnclave::CreatePassportReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // For hyperenclave, there is no external reference data
  // BackgroundCheck and Passport type report has the same json_report
  TEE_CHECK_RETURN(CreateBgcheckReport(param, report));

  // So, only change the report here.
  report->set_str_report_type(kUaReportTypePassport);

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
