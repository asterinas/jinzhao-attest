#ifndef UAL_VERIFICATION_PLATFORMS_CSV_VERIFIER_CSV_H_
#define UAL_VERIFICATION_PLATFORMS_CSV_VERIFIER_CSV_H_

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
class AttestationVerifierCsv : public AttestationVerifierInterface {
 public:
  TeeErrorCode Initialize(
      const kubetee::UnifiedAttestationReport& report) override;
  TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr) override;
  TeeErrorCode GetReportQuote(std::string* quote) override;

 private:
  TeeErrorCode ParseAttributes();
  TeeErrorCode VerifyCertChain(const kubetee::HygonCsvCertChain& cert_chain,
                               csv_attestation_report* report);
  TeeErrorCode VerifyReportSignature(csv_attestation_report* report);
  TeeErrorCode RetrieveData(kubetee::common::DataBytes* data, uint32_t key);

  std::string b64_report_;
  kubetee::common::DataBytes report_;
  kubetee::HygonCsvCertChain cert_chain_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_PLATFORMS_CSV_VERIFIER_CSV_H_
