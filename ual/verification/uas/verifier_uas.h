#ifndef UAL_VERIFICATION_UAS_VERIFIER_UAS_H_
#define UAL_VERIFICATION_UAS_VERIFIER_UAS_H_

#include <string>
#include <vector>

#include "./sgx_quote.h"
#include "./sgx_report.h"

#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace attestation {

// Only verify the SGX EPID mode remote attestation report here.
// The type of report is checked and dispatched in AttestationVerifier
class AttestationVerifierUas : public AttestationVerifierInterface {
 public:
  TeeErrorCode Initialize(
      const kubetee::UnifiedAttestationReport& report) override;
  TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr) override;
  TeeErrorCode GetReportQuote(std::string* quote) override;

 private:
  // Top check functions when parse report
  TeeErrorCode CheckReportSignature();

  // Functions to parse the UAS report
  TeeErrorCode ParseUasReport(const kubetee::UasReport& uas_report);
  TeeErrorCode ParseUasResponse(
      const kubetee::UasAttestionResult& uas_response);
  TeeErrorCode ParseQuoteSPID(sgx_quote_t* pquote);
  TeeErrorCode ParseQuoteReportBody(sgx_quote_t* pquote);

  kubetee::UasReport uas_report_;
  std::string b64_quote_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_UAS_VERIFIER_UAS_H_
