#ifndef UAL_INCLUDE_ATTESTATION_VERIFICATION_CORE_VERIFIER_H_
#define UAL_INCLUDE_ATTESTATION_VERIFICATION_CORE_VERIFIER_H_

#include <memory>
#include <string>

#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace attestation {

class AttestationVerifier {
 public:
  AttestationVerifier() {
    is_initialized_ = false;
  }
  ~AttestationVerifier() {}

  TeeErrorCode Initialize(const kubetee::UnifiedAttestationReport& report);
  TeeErrorCode Verify(const kubetee::UnifiedAttestationPolicy& policy);
  TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr);
  TeeErrorCode GetAttesterAttr(kubetee::UnifiedAttestationAttributes* attr);
  TeeErrorCode GetReportQuote(std::string* quote);
  TeeErrorCode CheckInitialized();

 private:
  std::shared_ptr<AttestationVerifierInterface> inner_;

  bool is_initialized_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_VERIFICATION_CORE_VERIFIER_H_
