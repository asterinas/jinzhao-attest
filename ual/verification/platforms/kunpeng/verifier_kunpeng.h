#ifndef UAL_VERIFICATION_PLATFORMS_KUNPENG_VERIFIER_KUNPENG_H_
#define UAL_VERIFICATION_PLATFORMS_KUNPENG_VERIFIER_KUNPENG_H_

#include <string>
#include <vector>

#include "./sgx_error.h"
#include "./sgx_quote_3.h"
#include "./sgx_report.h"

#include "./pccs.pb.h"

#include "attestation/common/bytes.h"
#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace attestation {

// Verify the Huawei Kunpeng platform remote attestation report here.
// The type of report is checked and dispatched in AttestationVerifier
class AttestationVerifierKunpeng : public AttestationVerifierInterface {
 public:
  TeeErrorCode Initialize(
      const kubetee::UnifiedAttestationReport& report) override;
  TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr) override;
  TeeErrorCode GetReportQuote(std::string* quote) override;

 private:
  // Parse the attester attributes from report
  TeeErrorCode ParseAttributes();

  std::string b64_quote_body_;
  kubetee::common::DataBytes quote_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_PLATFORMS_KUNPENG_VERIFIER_KUNPENG_H_
