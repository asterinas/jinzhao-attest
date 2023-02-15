#ifndef UAL_INCLUDE_ATTESTATION_GENERATION_CORE_GENERATOR_H_
#define UAL_INCLUDE_ATTESTATION_GENERATION_CORE_GENERATOR_H_

#include <memory>
#include <string>

#include "attestation/generation/core/generator_interface.h"

namespace kubetee {
namespace attestation {

// AttestationGenerator create attestation report for specified enclave
// instance.
class AttestationGenerator {
 public:
  TeeErrorCode Initialize(const std::string& tee_identity);

  // Create the attestation report
  TeeErrorCode GenerateReport(const UaReportGenerationParameters& param,
                              kubetee::UnifiedAttestationReport* report);

  // Verify the submodules reports inside TEE
  TeeErrorCode VerifySubReportsTrusted(
      const kubetee::UnifiedAttestationAuthReports& auth_reports,
      const kubetee::UnifiedAttestationPolicy& policy,
      std::string* results_json);

  // Get the attester attributes
  TeeErrorCode GetAttesterAttr(kubetee::UnifiedAttestationAttributes* attr);

 private:
  std::shared_ptr<AttestationGeneratorInterface> inner_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_GENERATION_CORE_GENERATOR_H_
