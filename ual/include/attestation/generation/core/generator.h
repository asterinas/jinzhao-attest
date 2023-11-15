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

  // Get the attester attributes
  TeeErrorCode GetAttesterAttr(kubetee::UnifiedAttestationAttributes* attr);

 private:
  std::shared_ptr<AttestationGeneratorInterface> inner_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_GENERATION_CORE_GENERATOR_H_
