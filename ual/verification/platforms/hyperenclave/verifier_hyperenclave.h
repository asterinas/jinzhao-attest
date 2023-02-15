#ifndef UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_VERIFIER_HYPERENCLAVE_H_
#define UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_VERIFIER_HYPERENCLAVE_H_

#include <string>
#include <vector>

#include "./sgx_quote.h"
#include "./sgx_report.h"

#include "attestation/common/bytes.h"
#include "attestation/verification/core/verifier_interface.h"
#include "verification/platforms/hyperenclave/platform.h"
#include "verification/platforms/hyperenclave/sm2.h"

namespace kubetee {
namespace attestation {

typedef struct platform_quote_sig_s {
  unsigned char enclave_sig[SM2_SIG_SIZE];
  unsigned char hv_att_key_pub[SM2_SIG_SIZE];
  unsigned char platform_attest[TPM_ATTEST_SIZE];
  unsigned char platform_sig[SM2_SIG_SIZE];
  unsigned char cert[];
} platform_quote_sig_t;

// Only verify the HyperEnclave platform remote attestation report here.
// The type of report is checked and dispatched in AttestationVerifier
class AttestationVerifierHyperEnclave : public AttestationVerifierInterface {
 public:
  TeeErrorCode Initialize(
      const kubetee::UnifiedAttestationReport& report) override;
  TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr) override;
  TeeErrorCode GetReportQuote(std::string* quote) override;

 private:
  // Signature verification related functions
  TeeErrorCode CheckEnclaveSignature(sgx_quote_t* pquote);
  TeeErrorCode CheckPlatformCertificate(sgx_quote_t* pquote);
  TeeErrorCode CheckPlatformAttestation(sgx_quote_t* pquote);
  TeeErrorCode CheckPlatformPcrList(sgx_quote_t* pquote);
  TeeErrorCode ParsePcrListFromCertificate(X509* x509);

  // Quote level functions when parse report
  TeeErrorCode ParseReportQuote();
  TeeErrorCode ParseQuoteSPID(sgx_quote_t* pquote);
  TeeErrorCode ParseQuoteReportBody(sgx_quote_t* pquote);

  // others
  int get_ext_data_offset(unsigned char* data);

  // Internal variables
  TPMS_ATTEST tpm_attest_;
  std::string tpm_signing_pubkey_;
  std::string pcr_list_;
  std::string b64_quote_body_;
  kubetee::common::DataBytes quote_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_VERIFIER_HYPERENCLAVE_H_
