#include <cstring>
#include <string>
#include <vector>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/scope.h"
#include "attestation/common/type.h"
#include "attestation/platforms/sgx_report_body.h"

#include "verification/platforms/sgx1/verifier_sgx_epid.h"

#include "rapidjson/document.h"

namespace kubetee {
namespace attestation {

constexpr char kStrQuoteStatus[] = "isvEnclaveQuoteStatus";
constexpr char kStrQuoteBody[] = "isvEnclaveQuoteBody";

// Intel official IAS CA
static const char* kAttestationSigningCACert = R"(
-----BEGIN CERTIFICATE-----
MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
DaVzWh5aiEx+idkSGMnX
-----END CERTIFICATE-----
)";

constexpr char kQuoteStatusOK[] = "OK";
constexpr char kQuoteStatusConfigurationNeeded[] = "CONFIGURATION_NEEDED";
constexpr char kQuoteStatusOutOfDate[] = "GROUP_OUT_OF_DATE";

TeeErrorCode AttestationVerifierSgxEpid::Initialize(
    const kubetee::UnifiedAttestationReport& report) {
  if (!report.json_nested_reports().empty()) {
    JSON2PB(report.json_nested_reports(), &nested_reports_);
  }
  report_type_ = report.str_report_type();

  // Check the platform
  if (report.str_tee_platform() != kUaPlatformSgxEpid) {
    ELOG_ERROR("It's not %s platform, input platform is [%s]",
               kUaPlatformSgxEpid, report.str_tee_platform().c_str());
    return TEE_ERROR_RA_VERIFY_ATTR_TEE_PLATFORM;
  }

#ifndef SGX_MODE_SIM
  if (report_type_ == kUaReportTypePassport) {
    // Parse the IasReport for Passport type report
    // Will save the attester attributes by the way.
    kubetee::common::DataBytes ias_report(report.json_report());
    TEE_CHECK_RETURN(ias_report.FromBase64().GetError());
    JSON2PB(ias_report.GetStr(), &ias_report_);
    TEE_CHECK_RETURN(ParseIasReport());
  } else
#endif
  {
    // Parse EpidReport f or SMI mode and BackgroundCheck type report
    kubetee::EpidReport epid_report;
    JSON2PB(report.json_report(), &epid_report);
    b64_quote_body_ = epid_report.b64_quote();
    TEE_CHECK_RETURN(ParseQuoteBody());
  }

  // Set the platform for UnifiedAttestationAttributes
  attributes_.set_str_tee_platform(kUaPlatformSgxEpid);

  // Show the attester attributes in report
  ELOG_DEBUG("Initialize EPID verifier successfully");
  TEE_CHECK_RETURN(ShowAttesterAttributes());
  return TEE_SUCCESS;
}

// The report response check
TeeErrorCode AttestationVerifierSgxEpid::VerifyPlatform(
    const kubetee::UnifiedAttestationAttributes& attr) {
  TEE_UNREFERENCED_PARAMETER(attr);

#ifndef SGX_MODE_SIM
  // Check the report type if the BackgroundCheck type return unsupport
  if (report_type_ == kUaReportTypeBgcheck) {
    ELOG_ERROR("BackgroundCheck type is not supported to be verified");
    return TEE_ERROR_RA_VERIFY_NEED_RERERENCE_DATA;
  }

  // Check the IAS report signature and status
  // Also the report sign type for SGX1 specail.
  TEE_CHECK_RETURN(CheckReportSignature());
  TEE_CHECK_RETURN(CheckReportQuoteStatus());
  TEE_CHECK_RETURN(CheckQuoteSignType());
#endif

  ELOG_DEBUG("Verify SGX1 Platform Successfully!");
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierSgxEpid::GetReportQuote(std::string* quote) {
  quote->assign(b64_quote_body_);
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierSgxEpid::ParseIasReport() {
  // Try to parse the quote status and body from IAS response body
  rapidjson::Document doc;
  if (!doc.Parse(ias_report_.json_response_body().data()).HasParseError()) {
    if (doc.HasMember(kStrQuoteStatus) && doc[kStrQuoteStatus].IsString()) {
      quote_status_.assign(doc[kStrQuoteStatus].GetString());
      ELOG_DEBUG("IAS quote status: %s", quote_status_.c_str());
    }
    if (doc.HasMember(kStrQuoteBody) && doc[kStrQuoteBody].IsString()) {
      b64_quote_body_.assign(doc[kStrQuoteBody].GetString());
      ELOG_DEBUG("IAS quote body: %s", b64_quote_body_.c_str());
    }
  }

  // Anyway, status and body is must required
  if (quote_status_.empty()) {
    ELOG_ERROR("Fail to parse ias quote status");
    return TEE_ERROR_RA_VERIFY_SGX1_PARSE_STATUS;
  }
  if (b64_quote_body_.empty()) {
    ELOG_ERROR("Fail to parse ias quote body");
    return TEE_ERROR_RA_VERIFY_SGX1_PARSE_BODY;
  }

  // Continue parse the quote body
  TEE_CHECK_RETURN(ParseQuoteBody());

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierSgxEpid::CheckReportSignature() {
  std::string b64_sig = ias_report_.b64_signature();
  std::string cert = ias_report_.str_signing_cert();
  std::string body = ias_report_.json_response_body();

  ELOG_BUFFER("[b64sig]", b64_sig.data(), b64_sig.length());
  if (b64_sig.empty() || cert.empty() || body.empty()) {
    ELOG_ERROR("Invalid IAS report response content!");
    return TEE_ERROR_RA_VERIFY_INVALID_IAS_REPORT;
  }

  BIO* root_cert = BIO_new(BIO_s_mem());
  BIO_puts(root_cert, kAttestationSigningCACert);
  ON_SCOPE_EXIT([&root_cert] { BIO_free(root_cert); });

  // Load intel CA
  X509* cert_ra = PEM_read_bio_X509(root_cert, NULL, NULL, NULL);
  if (cert_ra == NULL) {
    ELOG_ERROR("Fail to read Intel X509 CA pem certificate");
    return TEE_ERROR_RA_VERIFY_LOAD_IAS_ROOT_CERT;
  }
  ON_SCOPE_EXIT([&cert_ra] { X509_free(cert_ra); });

  // Build Cert-Chain
  const char* certchain = cert.c_str();
  uint32_t certchain_len = SCAST(uint32_t, strlen(certchain));
  X509_STORE* store = X509_STORE_new();
  X509_STORE_CTX* ctx = X509_STORE_CTX_new();
  X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
  BIO* bio_cert_chain = BIO_new_mem_buf(certchain, certchain_len);
  STACK_OF(X509)* recips = sk_X509_new_null();
  STACK_OF(X509_INFO)* inf =
      PEM_X509_INFO_read_bio(bio_cert_chain, NULL, NULL, NULL);
  ON_SCOPE_EXIT([&inf, &recips, &ctx, &store, &bio_cert_chain] {
    if (inf) {
      sk_X509_INFO_pop_free(inf, X509_INFO_free);
    }
    if (recips) {
      sk_X509_free(recips);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    BIO_free(bio_cert_chain);
  });

  if (inf == NULL || recips == NULL) {
    ELOG_ERROR("bad bio cert chain info");
    return TEE_ERROR_CRYPTO_CERT_LOAD;
  }

  // STEP: verify signing cert via intel CA
  if (X509_STORE_CTX_init(ctx, store, cert_ra, NULL) != 1) {
    ELOG_ERROR("init store ctx fail");
    return TEE_ERROR_CRYPTO_CERT_CTX_INIT;
  }

  for (int i = 0; i < sk_X509_INFO_num(inf); i++) {
    X509_INFO* info = sk_X509_INFO_value(inf, i);
    if (info && info->x509) {
      sk_X509_push(recips, info->x509);
    }
  }

  X509_STORE_CTX_trusted_stack(ctx, recips);

  if (X509_verify_cert(ctx) != 1) {
    ELOG_ERROR("Fail to verify IAS_signing certificate");
    return TEE_ERROR_CRYPTO_CERT_VERIFY;
  }

  // STEP: verify signature on response via signing cert
  BIO* bio_sp = BIO_new(BIO_s_mem());
  BIO_write(bio_sp, certchain, certchain_len);
  ON_SCOPE_EXIT([&bio_sp] { BIO_free_all(bio_sp); });

  X509* cert_sp = PEM_read_bio_X509(bio_sp, NULL, NULL, NULL);
  if (cert_sp == NULL) {
    ELOG_ERROR("Cannot read x509 from signing cert");
    return TEE_ERROR_CRYPTO_CERT_LOAD;
  }
  ON_SCOPE_EXIT([&cert_sp] { X509_free(cert_sp); });

  EVP_PKEY* pubkey_sp = X509_get_pubkey(cert_sp);
  if (pubkey_sp == NULL) {
    ELOG_ERROR("Cannot get EVP_PKEY from ias_signing_cert");
    return TEE_ERROR_RA_VERIFY_GET_PUBKEY;
  }
  ON_SCOPE_EXIT([&pubkey_sp] { EVP_PKEY_free(pubkey_sp); });

  RSA* rsa = EVP_PKEY_get1_RSA(pubkey_sp);
  if (rsa == NULL) {
    ELOG_ERROR("Cannot get RSA from EVP_PKEY");
    return TEE_ERROR_RA_VERIFY_GET_RSAKEY;
  }
  ON_SCOPE_EXIT([&rsa] { RSA_free(rsa); });

  // STEP: begin verify response body
  kubetee::common::DataBytes body_hash(body);
  if (body_hash.ToSHA256().empty()) {
    ELOG_ERROR("Fail to compute SHA256 for response");
    return TEE_ERROR_CRYPTO_SHA256;
  }
  ELOG_BUFFER("ReportResponse HASH", body_hash.data(), body_hash.size());

  kubetee::common::DataBytes signature(b64_sig);
  signature.FromBase64().Void();
  ELOG_BUFFER("SIGNATURE", signature.data(), signature.size());

  if (OPENSSL_SUCCESS != RSA_verify(NID_sha256, body_hash.data(),
                                    body_hash.size(), signature.data(),
                                    SCAST(uint32_t, signature.size()), rsa)) {
    ELOG_ERROR("Signature verification failed: 0x%ld", ERR_get_error());
    return TEE_ERROR_RA_VERIFY_SIGNATURE;
  }

  ELOG_DEBUG("Verify Signature Successfully!");
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierSgxEpid::CheckReportQuoteStatus() {
  const std::string& quote_status = quote_status_;
  const std::string& str_advisory_url = ias_report_.str_advisory_url();
  const std::string& str_advisory_ids = ias_report_.str_advisory_ids();

  if (quote_status == kQuoteStatusOK) {
    ELOG_DEBUG("Verify quote status: OK");
  } else if ((quote_status == kQuoteStatusConfigurationNeeded) ||
             (quote_status == kQuoteStatusOutOfDate)) {
    ELOG_WARN("Verify quote status: %s", quote_status.c_str());
    if (!str_advisory_url.empty()) {
      ELOG_WARN("AdvisoryUrl: %s", str_advisory_url.c_str());
    }
    if (!str_advisory_ids.empty()) {
      ELOG_WARN("AdvisoryIDs: %s", str_advisory_ids.c_str());
    }
  } else {
    ELOG_ERROR("Verify quote status: %s", quote_status.c_str());
    return TEE_ERROR_RA_VERIFY_ERROR_QUOTE_STATUS;
  }
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierSgxEpid::CheckQuoteSignType() {
  if (quote_sign_type_ != SGX_LINKABLE_SIGNATURE) {
    ELOG_ERROR("Unexpected sign type %d", quote_sign_type_);
    return TEE_ERROR_RA_VERIFY_SIGNING_TYPE;
  }
  return TEE_SUCCESS;
}

// The quote in response check:
//    typedef struct _quote_t {
//        uint16_t            version;
//        uint16_t            sign_type;
//        sgx_epid_group_id_t epid_group_id;
//        sgx_isv_svn_t       qe_svn;
//        sgx_isv_svn_t       pce_svn;
//        uint32_t            xeid;
//        sgx_basename_t      basename;
//        sgx_report_body_t   report_body;
//        uint32_t            signature_len;
//        uint8_t             signature[];
//    } sgx_quote_t;
TeeErrorCode AttestationVerifierSgxEpid::ParseQuoteBody() {
  kubetee::common::DataBytes quote(b64_quote_body_);
  TEE_CHECK_RETURN(quote.FromBase64().GetError());
  ELOG_BUFFER("QUOTE", quote.data(), quote.size());
  sgx_quote_t* pquote = RCAST(sgx_quote_t*, quote.data());

  TEE_CHECK_RETURN(ParseQuoteSignType(pquote));
  TEE_CHECK_RETURN(ParseQuoteSPID(pquote));
  TEE_CHECK_RETURN(ParseQuoteReportBody(pquote));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierSgxEpid::ParseQuoteSignType(
    sgx_quote_t* pquote) {
  TEE_CHECK_NULLPTR(pquote);

  quote_sign_type_ = pquote->sign_type;
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierSgxEpid::ParseQuoteSPID(sgx_quote_t* pquote) {
  TEE_CHECK_NULLPTR(pquote);
  // sgx_basename_t is 2 times of sgx_spid_t, we just use the firs half bytes
  kubetee::common::DataBytes spid(RCAST(uint8_t*, pquote->basename.name),
                                  sizeof(sgx_spid_t));
  attributes_.set_hex_spid(spid.ToHexStr().GetStr());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierSgxEpid::ParseQuoteReportBody(
    sgx_quote_t* pquote) {
  TEE_CHECK_NULLPTR(pquote);
  sgx_report_body_t* report_body = &(pquote->report_body);
  kubetee::common::platforms::SgxReportBodyParser report_body_parser;
  TEE_CHECK_RETURN(
      report_body_parser.ParseReportBody(report_body, &attributes_));
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
