#ifndef UAL_VERIFICATION_PLATFORMS_CSV_VERIFIER_TDX_H_
#define UAL_VERIFICATION_PLATFORMS_CSV_VERIFIER_TDX_H_

#include <string>
#include <vector>

#include "./sgx_error.h"
#include "./sgx_quote_3.h"
#include "./sgx_report.h"

#include "./pccs.pb.h"

#include "attestation/common/bytes.h"
#include "attestation/common/type.h"
#include "attestation/platforms/csv.h"

#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace attestation {

// Only verify the CSV platform remote attestation report here.
// The type of report is checked and dispatched in AttestationVerifier
class AttestationVerifierTdx : public AttestationVerifierInterface {
 public:
  TeeErrorCode Initialize(
      const kubetee::UnifiedAttestationReport& report) override;
  TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr) override;
  TeeErrorCode GetReportQuote(std::string* quote) override;

 private:
  TeeErrorCode ParseAttributes();

  std::string b64_report_;
  kubetee::common::DataBytes report_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_PLATFORMS_CSV_VERIFIER_TDX_H_
