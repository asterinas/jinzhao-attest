#include <memory>
#include <string>

#include "attestation/common/log.h"

#include "attestation/verification/core/verifier.h"
#include "verification/platforms/csv/verifier_csv.h"
#include "verification/platforms/hyperenclave/verifier_hyperenclave.h"
#include "verification/platforms/kunpeng/verifier_kunpeng.h"
#include "verification/platforms/sgx1/verifier_sgx_epid.h"
#include "verification/platforms/sgx2/verifier_sgx_dcap.h"
#include "verification/platforms/tdx/verifier_tdx.h"
#include "verification/uas/verifier_uas.h"

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationVerifier::Initialize(
    const kubetee::UnifiedAttestationReport& report) {
  const std::string& platform = report.str_tee_platform();
  if (report.str_report_type() == kUaReportTypeUas) {
    // For UAS report, it has nothing to do with different platform details
    inner_ = std::make_shared<AttestationVerifierUas>();
  } else {
    if (platform == kUaPlatformHyperEnclave) {
      inner_ = std::make_shared<AttestationVerifierHyperEnclave>();
    } else if (platform == kUaPlatformSgxEpid) {
      inner_ = std::make_shared<AttestationVerifierSgxEpid>();
    } else if (platform == kUaPlatformSgxDcap) {
      inner_ = std::make_shared<AttestationVerifierSgxDcap>();
    } else if (platform == kUaPlatformCsv) {
      inner_ = std::make_shared<AttestationVerifierCsv>();
    } else if (platform == kUaPlatformTdx) {
      inner_ = std::make_shared<AttestationVerifierTdx>();
    } else if (platform == kUaPlatformKunpeng) {
      inner_ = std::make_shared<AttestationVerifierKunpeng>();
    } else {
      ELOG_ERROR("Unsupported TEE platform: %s", platform.c_str());
      return TEE_ERROR_UNSUPPORTED_TEE;
    }
  }

  TEE_CHECK_RETURN(inner_->Initialize(report));
  is_initialized_ = true;
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifier::Verify(
    const kubetee::UnifiedAttestationPolicy& policy) {
  TEE_CHECK_RETURN(CheckInitialized());
  TEE_CHECK_RETURN(inner_->Verify(policy));
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifier::VerifyPlatform(
    const kubetee::UnifiedAttestationAttributes& attr) {
  TEE_CHECK_RETURN(CheckInitialized());
  TEE_CHECK_RETURN(inner_->VerifyPlatform(attr));
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifier::GetAttesterAttr(
    kubetee::UnifiedAttestationAttributes* attr) {
  TEE_CHECK_RETURN(CheckInitialized());
  TEE_CHECK_RETURN(inner_->GetAttesterAttr(attr));
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifier::GetReportQuote(std::string* quote) {
  TEE_CHECK_RETURN(CheckInitialized());
  TEE_CHECK_RETURN(inner_->GetReportQuote(quote));
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifier::CheckInitialized() {
  if (!is_initialized_) {
    return TEE_ERROR_RA_VERIFY_NOT_INITIALIZED;
  }
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
