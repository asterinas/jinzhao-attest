#ifndef UAL_VERIFICATION_PLATFORMS_SGX1_VERIFIER_SGX_EPID_H_
#define UAL_VERIFICATION_PLATFORMS_SGX1_VERIFIER_SGX_EPID_H_

#include <string>
#include <vector>

#include "./sgx_quote.h"
#include "./sgx_report.h"

#include "attestation/common/bytes.h"
#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace attestation {

// Only verify the SGX EPID platform remote attestation report here.
// The type of report is checked and dispatched in AttestationVerifier
class AttestationVerifierSgxEpid : public AttestationVerifierInterface {
 public:
  TeeErrorCode Initialize(
      const kubetee::UnifiedAttestationReport& report) override;
  TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr) override;
  TeeErrorCode GetReportQuote(std::string* quote) override;

 private:
  // Top check functions when parse IAS report
  TeeErrorCode CheckReportSignature();
  TeeErrorCode CheckReportQuoteStatus();
  TeeErrorCode CheckQuoteSignType();

  // Functions when parse IAS report and quote
  TeeErrorCode ParseIasReport();
  TeeErrorCode ParseQuoteBody();
  TeeErrorCode ParseQuoteSignType(sgx_quote_t* pquote);
  TeeErrorCode ParseQuoteSPID(sgx_quote_t* pquote);
  TeeErrorCode ParseQuoteReportBody(sgx_quote_t* pquote);

  uint16_t quote_sign_type_;
  std::string quote_status_;
  std::string b64_quote_body_;
  kubetee::IasReport ias_report_;
  kubetee::common::DataBytes quote_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_PLATFORMS_SGX1_VERIFIER_SGX_EPID_H_
