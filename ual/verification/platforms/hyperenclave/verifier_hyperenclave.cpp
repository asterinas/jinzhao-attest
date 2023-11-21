#include <cstring>
#include <string>
#include <vector>

#include "openssl/err.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/scope.h"
#include "attestation/common/type.h"
#include "attestation/platforms/sgx_report_body.h"

#include "verification/platforms/hyperenclave/sm2.h"
#include "verification/platforms/hyperenclave/verifier_hyperenclave.h"

namespace kubetee {
namespace attestation {

constexpr char kUserId[SM2_USERID_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05,
                                           0x06, 0x07, 0x08, 0x09, 0x0A,
                                           0x0B, 0x0C, 0x0D, 0x0E};
constexpr char kSm2PubId[] = {0x04};

TeeErrorCode AttestationVerifierHyperEnclave::Initialize(
    const kubetee::UnifiedAttestationReport& report) {
  if (!report.json_nested_reports().empty()) {
    JSON2PB(report.json_nested_reports(), &nested_reports_);
  }
  report_type_ = report.str_report_type();

  // Check the platform
  if (report.str_tee_platform() != kUaPlatformHyperEnclave) {
    ELOG_ERROR("It's not %s platfrom, input platform is [%s]",
               kUaPlatformHyperEnclave, report.str_tee_platform().c_str());
    return TEE_ERROR_RA_VERIFY_ATTR_TEE_PLATFORM;
  }

  // Get the sgx_quote_t data
  ELOG_DEBUG("Report: %s", report.json_report().c_str());
  if (report.json_report().empty()) {
    ELOG_ERROR("Empty json report string!");
    return TEE_ERROR_PARAMETERS;
  }
  kubetee::HyperEnclaveReport hyper_report;
  JSON2PB(report.json_report(), &hyper_report);
  b64_quote_body_ = hyper_report.b64_quote();
  quote_.SetValue(b64_quote_body_);
  TEE_CHECK_RETURN(quote_.FromBase64().GetError());

  // Parse the attester attributes in quote
  TEE_CHECK_RETURN(ParseReportQuote());

  // Set the platform for UnifiedAttestationAttributes
  attributes_.set_str_tee_platform(kUaPlatformHyperEnclave);

  // Set the hex_spid empty
  attributes_.set_hex_spid("");

  // Show the attester attributes in report
  ELOG_DEBUG("Initialize hyperenclave verifier successfully");
  TEE_CHECK_RETURN(ShowAttesterAttributes());
  return TEE_SUCCESS;
}

// The report response check
TeeErrorCode AttestationVerifierHyperEnclave::VerifyPlatform(
    const kubetee::UnifiedAttestationAttributes& attr) {
  // The certificate includes the TPM PCRs and TPM public key
  // 1. Verify the signatures from the peer certificate by hard code cert chain
  // 2. The platform attest data is signed by TPM private key and verified here
  // 3. The PCRs digest in platform attest is checked via PCRS in certificate
  // Because the HyperEnclave public key is also extended to PCRs,
  // and the PCRs measurement also includes the hash of HyperEnclave public key,
  // So, the public key is trusted and used to verify the report body.
  sgx_quote_t* pquote = RCAST(sgx_quote_t*, quote_.data());
  // If the user_data in attributs is empty, should also consider the
  // defualt public hash if public_key_ is not empty.
  // Use the same logic in generation code to convert user_data
  // to full report_data
  TEE_UNREFERENCED_PARAMETER(attr);

  ELOG_DEBUG("Report signature length: %d", pquote->signature_len);

  // Verify the certificate in the signature structure
  // And get the trused TPM signing public key and PCRs
  TEE_CHECK_RETURN(CheckPlatformCertificate(pquote));

  // Verify the attestation signature via TPM signing public key
  TEE_CHECK_RETURN(CheckPlatformAttestation(pquote));

  // Verify the report_body signature via Hyperencalve signin public key
  TEE_CHECK_RETURN(CheckEnclaveSignature(pquote));

  ELOG_DEBUG("Verify HyperEnclave Platform Successfully!");
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierHyperEnclave::GetReportQuote(
    std::string* quote) {
  quote->assign(b64_quote_body_);
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierHyperEnclave::CheckPlatformCertificate(
    sgx_quote_t* pquote) {
  platform_quote_sig_t* psig = RCAST(platform_quote_sig_t*, pquote->signature);
  int sig_len = sizeof(platform_quote_sig_t);
  int cert_len = pquote->signature_len - sig_len;
  ELOG_DEBUG("cert length=%d, signature other length=%d", cert_len, sig_len);
  if (cert_len <= 0 || cert_len > DER_CERT_BUF_SIZE) {
    ELOG_ERROR("Invalid cert length: %d", cert_len);
    ELOG_BUFFER("CERT", psig->cert, cert_len);
    return TEE_ERROR_RA_VERIFY_PLATFORM_CERT_LEN;
  }

  // Verify the certificate firstly
  const uint8_t* pcert = RCAST(uint8_t*, psig->cert);
  if (!verify_peer_cert(CCAST(uint8_t*, pcert), cert_len)) {
    return TEE_ERROR_CRYPTO_CERT;
  }

  // Get the TPM public key from certificate
  UniqueX509 peer_x509(d2i_X509(NULL, &pcert, cert_len), X509_free);
  if (peer_x509.get() == nullptr) {
    ELOG_ERROR("Fail to load peer certificate");
    return TEE_ERROR_CRYPTO_CERT;
  }
  UniquePkey pkey(X509_get_pubkey(peer_x509.get()), EVP_PKEY_free);
  if (pkey.get() == nullptr) {
    ELOG_ERROR("Fail to get public key from certificate");
    return TEE_ERROR_CRYPTO_CERT;
  }
  UniqueEcKey eckey(EVP_PKEY_get1_EC_KEY(pkey.get()), EC_KEY_free);
  if (eckey.get() == nullptr) {
    ELOG_ERROR("Fail to get the EC key from public key");
    return TEE_ERROR_CRYPTO_CERT;
  }
  const EC_GROUP* group = EC_KEY_get0_group(eckey.get());
  const EC_POINT* point = EC_KEY_get0_public_key(eckey.get());
  sm2_pub_key_t pubkey;
  size_t keylen = sizeof(sm2_pub_key_t);
  if (keylen != EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                   pubkey.key, keylen, NULL)) {
    ELOG_ERROR("Can not get the TPM pub key");
    return TEE_ERROR_CRYPTO_CERT;
  }
  tpm_signing_pubkey_.assign(RCCHAR(pubkey.key), keylen);

  // Parse the TPM PCRs in the certificate extension
  TEE_CHECK_RETURN(ParsePcrListFromCertificate(peer_x509.get()));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierHyperEnclave::CheckPlatformPcrList(
    sgx_quote_t* pquote) {
  platform_quote_sig_t* psig = RCAST(platform_quote_sig_t*, pquote->signature);

  // Verify the PCR List
  if (!verify_pcr_digest(
          &tpm_attest_, psig->hv_att_key_pub, sizeof(psig->hv_att_key_pub),
          RCCAST(uint8_t*, pcr_list_.data()), pcr_list_.size())) {
    ELOG_ERROR("Fail to verify platform PCR digest");
    return TEE_ERROR_RA_VERIFY_PCR_DIGEST;
  }
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierHyperEnclave::ParsePcrListFromCertificate(
    X509* x509) {
  char extname[128];
  const char* self_ext_name = "1.2.86.1";

  const STACK_OF(X509_EXTENSION)* extensions = X509_get0_extensions(x509);
  if (!extensions) {
    ELOG_ERROR("Fail to get extensions in X509 cert");
    return TEE_ERROR_CRYPTO_CERT;
  }
  int num_of_exts = sk_X509_EXTENSION_num(extensions);
  if (num_of_exts <= 0) {
    ELOG_ERROR("No extensions in X509 cert ");
    return TEE_ERROR_CRYPTO_CERT;
  }
  for (int i = 0; i < num_of_exts; i++) {
    X509_EXTENSION* extension = sk_X509_EXTENSION_value(extensions, i);
    if (!extension) {
      ELOG_ERROR("Invalid extension in X509 cert");
      return TEE_ERROR_CRYPTO_CERT;
    }
    ASN1_OBJECT* obj = X509_EXTENSION_get_object(extension);
    if (OBJ_obj2nid(obj) != 0) {
      continue;
    }

    memset(extname, 0, sizeof(extname));
    OBJ_obj2txt(extname, sizeof(extname), (const ASN1_OBJECT*)obj, 1);
    if (memcmp(extname, self_ext_name, strlen(self_ext_name)) != 0) {
      ELOG_ERROR("Invalid ext_name: %s", extname);
      return TEE_ERROR_CRYPTO_CERT;
    }
    // ASN1_VALUE format:
    //  0xOC(UTFSTRING tag)
    //  82(len header, 2byte length later)
    //  <2bytes-len-of-base64>
    ASN1_OCTET_STRING* ext_str = X509_EXTENSION_get_data(extension);
    int ans1_header_len = get_ext_data_offset(ext_str->data);
    ELOG_DEBUG("ext_str: %s", ext_str->data + ans1_header_len);
    uint8_t* b64_value = ext_str->data + ans1_header_len;
    size_t b64_len = ext_str->length - ans1_header_len;
    kubetee::common::DataBytes pcr_str(b64_value, b64_len);
    pcr_list_.assign(pcr_str.FromBase64().GetStr());
    ELOG_DEBUG("PCR baseline=%s", pcr_str.ToHexStr().GetStr().c_str());
  }
  return TEE_SUCCESS;
}

int AttestationVerifierHyperEnclave::get_ext_data_offset(uint8_t* data) {
  uint8_t* ptr;
  ptr = data;
  // utf8-string
  if (*ptr != 0x0c) {
    return 0;
  }
  ptr++;
  return (*ptr <= 0x80) ? 2 : (2 + (*ptr - 0x80));
}

TeeErrorCode AttestationVerifierHyperEnclave::CheckPlatformAttestation(
    sgx_quote_t* pquote) {
  platform_quote_sig_t* psig = RCAST(platform_quote_sig_t*, pquote->signature);

  // Verify the attestation signature
  std::string data_str(RCCHAR(psig->platform_attest), TPM_ATTEST_SIZE);
  std::string sig_str(RCCHAR(psig->platform_sig), SM2_SIG_SIZE);
  std::string user_id(kUserId, sizeof(kUserId));
  TEE_CHECK_RETURN(
      Sm2Crypto::Verify(data_str, user_id, tpm_signing_pubkey_, sig_str));

  // Get the TPM attestation data
  init_tpms_attest(&tpm_attest_);
  if (!decode_tpm_attest_data(psig->platform_attest, TPM_ATTEST_SIZE,
                              &tpm_attest_)) {
    ELOG_ERROR("decode_tpm_attest_data failed\n");
    return TEE_ERROR_CRYPTO_CERT;
  }
  ELOG_BUFFER("TPM_ATTEST", &tpm_attest_, sizeof(TPMS_ATTEST));
  ELOG_BUFFER("TPM_ATTEST_tpm_generated", &tpm_attest_.tpm_generated,
              sizeof(uint32_t));
  ELOG_BUFFER("TPM_ATTEST_signer", &tpm_attest_.signer, sizeof(TPM2B_NAME));
  ELOG_BUFFER("TPM_ATTEST_extra_data", &tpm_attest_.extra_data,
              sizeof(TPM2B_DATA));
  ELOG_BUFFER("TPM_ATTEST_quote.pcr_select", &tpm_attest_.quote.pcr_select,
              sizeof(TPML_PCR_SELECTION));
  ELOG_BUFFER("TPM_ATTEST_quote.pcr_digest", &tpm_attest_.quote.pcr_digest,
              sizeof(TPML_PCR_SELECTION));

  // Also calculate the PCSs digest in certificate and compare to
  // which in attestation data, this digest in attestation data is
  // calculated based on current platform status when create
  // attestation report each time.
  TEE_CHECK_RETURN(CheckPlatformPcrList(pquote));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierHyperEnclave::CheckEnclaveSignature(
    sgx_quote_t* pquote) {
  platform_quote_sig_t* psig = RCAST(platform_quote_sig_t*, pquote->signature);

  // Get the report_body as data
  std::string data_str(RCCHAR(&pquote->report_body), sizeof(sgx_report_body_t));
  // Get the sm2_signaure_t type signature
  std::string sig_str(RCCHAR(psig->enclave_sig), SM2_SIG_SIZE);
  // Get the sm2_pub_key_t type public key with public key ID;
  std::string pubkey(kSm2PubId, 1);
  pubkey.append(RCCHAR(psig->hv_att_key_pub), SM2_SIG_SIZE);
  // Get the UsedrID
  std::string user_id(kUserId, sizeof(kUserId));

  TEE_CHECK_RETURN(Sm2Crypto::VerifyUseZ(data_str, user_id, pubkey, sig_str));
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
TeeErrorCode AttestationVerifierHyperEnclave::ParseReportQuote() {
  sgx_quote_t* pquote = RCAST(sgx_quote_t*, quote_.data());
  TEE_CHECK_RETURN(ParseQuoteSPID(pquote));
  TEE_CHECK_RETURN(ParseQuoteReportBody(pquote));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierHyperEnclave::ParseQuoteSPID(
    sgx_quote_t* pquote) {
  TEE_CHECK_NULLPTR(pquote);
  // sgx_basename_t is 2 times of sgx_spid_t, we just use the firs half bytes
  kubetee::common::DataBytes spid(RCAST(uint8_t*, pquote->basename.name),
                                  sizeof(sgx_spid_t));
  attributes_.set_hex_spid(spid.ToHexStr().GetStr());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierHyperEnclave::ParseQuoteReportBody(
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
