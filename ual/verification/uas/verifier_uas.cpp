#include <cstring>
#include <string>
#include <vector>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"

#include "attestation/common/asymmetric_crypto.h"
#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/scope.h"
#include "attestation/common/type.h"
#include "attestation/platforms/sgx_report_body.h"

#include "verification/uas/verifier_uas.h"

namespace kubetee {
namespace attestation {

#ifdef SM_MODE
static const char* gUasPublcKey = R"(
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE/EmKRWESPNO9TJfBF8KXAfnuh0OY
daxZTgVeb4zfkBSqJFY66I9KhDpZqE05G6f8mKzZwde/QZtTShDPR7uBIA==
-----END PUBLIC KEY-----
)";
#else
static const char* gUasPublcKey = R"(
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAmOokOoFS9TKY5uPZKH/uGJO23tZV4y1G9YcqZErRNC8PrEPYrllx
N750MWN9WmOK18O7Lm2sR2Rl+DUy1xiOaJiQHLX7SFuiMqn3+sdCLLZq8B4nalj4
bxMnTxz6QOk7P5Me9KM1+H/2sA+bIrTHrxzkGw5lKDxWHwCGDPfBw8GpZQ6ViWT9
SeF4mN6Pchb5J132l5P6WRgrAEkvuQ+P41hP8tyRShuI+pQGqiQAByxzhsFqg8/I
5DTVkxUV16oHdlzltwH8zSTvCGrxBayfgNcKcv2gFnQf/H+VusIGiz2saYx2Nos/
aptZvSJjcC7s7SKB+l0ttq0Na90iQrTISQIDAQAB
-----END RSA PUBLIC KEY-----
)";
#endif

TeeErrorCode AttestationVerifierUas::Initialize(
    const kubetee::UnifiedAttestationReport& report) {
  // Parse the UAS report to get the report_body, attester attributes.
  JSON2PB(report.json_report(), &uas_report_);
  TEE_CHECK_RETURN(ParseUasReport(uas_report_));

  // Show the attester attributes in report
  ELOG_DEBUG("Initialize UAS verifier successfully");
  TEE_CHECK_RETURN(ShowAttesterAttributes());
  return TEE_SUCCESS;
}

// The report response check
TeeErrorCode AttestationVerifierUas::VerifyPlatform(
    const kubetee::UnifiedAttestationAttributes& attr) {
  TEE_UNREFERENCED_PARAMETER(attr);
  // The platform is verified in UAS Server side
  // Here, we only check the signature to the attestation result
  TEE_CHECK_RETURN(CheckReportSignature());
  return TEE_SUCCESS;
}

// The report response check
TeeErrorCode AttestationVerifierUas::GetReportQuote(std::string* quote) {
  quote->assign(b64_quote_);
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierUas::CheckReportSignature() {
  std::string public_key = std::string(gUasPublcKey);
  ELOG_DEBUG("UAS signature: %s", uas_report_.b64_signature().c_str());
  ELOG_DEBUG("UAS response: %s", uas_report_.json_result().c_str());

  // verify the signature
  // if gUasPublcKey type is rsa_public_key, sm_mode = false;
  kubetee::common::DataBytes uas_qoute_sig_b64(uas_report_.b64_signature());
  kubetee::common::AsymmetricCrypto asymmetric_crypto;
  bool sm_mode = asymmetric_crypto.isSmMode(public_key);
  TEE_CHECK_RETURN(asymmetric_crypto.Verify(
      public_key.c_str(), uas_report_.json_result(),
      uas_qoute_sig_b64.FromBase64().GetStr(), sm_mode));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierUas::ParseUasReport(
    const kubetee::UasReport& uas_report) {
  // Parse b64_quote in uas_report
  ELOG_DEBUG("UAS result: %s", uas_report.json_result().c_str());
  if (uas_report.json_result().empty()) {
    ELOG_ERROR("UAS json_result is empty");
    return TEE_ERROR_RA_VERIFY_UAS_RESULT_EMPTY;
  }
  kubetee::UasAttestionResult uas_result;
  JSON2PB(uas_report.json_result(), &uas_result);
  TEE_CHECK_RETURN(ParseUasResponse(uas_result));

  // Parse the quote to get enclave inforamtion
  kubetee::common::DataBytes quote(b64_quote_);
  TEE_CHECK_RETURN(quote.FromBase64().GetError());
  ELOG_BUFFER("QUOTE", quote.data(), quote.size());
  sgx_quote_t* pquote = RCAST(sgx_quote_t*, quote.data());
  TEE_CHECK_RETURN(ParseQuoteSPID(pquote));
  TEE_CHECK_RETURN(ParseQuoteReportBody(pquote));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierUas::ParseUasResponse(
    const kubetee::UasAttestionResult& uas_result) {
  // Check the quote body
  b64_quote_ = uas_result.b64_quote();
  ELOG_DEBUG("quote body: %s", b64_quote_.c_str());
  if (b64_quote_.empty()) {
    ELOG_ERROR("No quote body in UAS report response!");
    return TEE_ERROR_RA_VERIFY_UAS_QUOTE_BODY_EMPTY;
  }
  // Check attestation reuslt code
  ELOG_DEBUG("uas result code: %d", uas_result.int64_result_code());
  if (uas_result.int64_result_code() != TEE_SUCCESS) {
    ELOG_ERROR("uas result code [0x%lX]", uas_result.int64_result_code());
    return TEE_ERROR_RA_VERIFY_UAS_RESULT_CODE;
  }

  // Set the platform for UnifiedAttestationAttributes
  attributes_.set_str_tee_platform(uas_result.str_tee_platform());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierUas::ParseQuoteSPID(sgx_quote_t* pquote) {
  TEE_CHECK_NULLPTR(pquote);
  // sgx_basename_t is 2 times of sgx_spid_t, we just use the firs half bytes
  kubetee::common::DataBytes spid(RCAST(uint8_t*, pquote->basename.name),
                                  sizeof(sgx_spid_t));
  attributes_.set_hex_spid(spid.ToHexStr().GetStr());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierUas::ParseQuoteReportBody(sgx_quote_t* pquote) {
  TEE_CHECK_NULLPTR(pquote);
  sgx_report_body_t* report_body = &(pquote->report_body);
  kubetee::common::platforms::SgxReportBodyParser report_body_parser;
  TEE_CHECK_RETURN(
      report_body_parser.ParseReportBody(report_body, &attributes_));
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
