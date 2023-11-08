#ifndef UAL_VERIFICATION_PLATFORMS_SGX2_VERIFIER_SGX_DCAP_H_
#define UAL_VERIFICATION_PLATFORMS_SGX2_VERIFIER_SGX_DCAP_H_

#include <string>
#include <vector>

#include "./sgx_error.h"
#include "./sgx_ql_lib_common.h"
#include "./sgx_quote_3.h"
#include "./sgx_report.h"

#include "./pccs.pb.h"

#include "attestation/common/bytes.h"
#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace attestation {

// Only verify the SGX DCAP platform remote attestation report here.
// The type of report is checked and dispatched in AttestationVerifier
class AttestationVerifierSgxDcap : public AttestationVerifierInterface {
 public:
  TeeErrorCode Initialize(
      const kubetee::UnifiedAttestationReport& report) override;
  TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr) override;
  TeeErrorCode GetReportQuote(std::string* quote) override;

 private:
  // call DCAP quote verify library to get supplemental data size
  TeeErrorCode SetCollateral(const char* n,
                             const std::string& s,
                             char** d,
                             uint32_t* l);
  TeeErrorCode InitializeCollateralData(
      const kubetee::SgxQlQveCollateral& collateral,
      sgx_ql_qve_collateral_t* collateral_data);
  TeeErrorCode QvlInitializeSupplementalData(std::string* supplemental);
  TeeErrorCode QvlVerifyReport(const kubetee::SgxQlQveCollateral& collateral,
                               const uint8_t* quote,
                               const size_t quote_size);

  // Quote level functions when parse sgx_quote3_t
  TeeErrorCode ParseQuoteReportBody();

  // TODO(junxian.xjx): avoid to repeat the b64 quote and bytes quote
  std::string b64_quote_body_;
  kubetee::common::DataBytes quote_;
  kubetee::SgxQlQveCollateral collateral_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_PLATFORMS_SGX2_VERIFIER_SGX_DCAP_H_
