#ifndef UAL_GENERATION_PLATFORMS_CSV_UNTRUSTED_GENERATOR_TDX_H_
#define UAL_GENERATION_PLATFORMS_CSV_UNTRUSTED_GENERATOR_TDX_H_

#include <map>
#include <memory>
#include <string>

#include "attestation/platforms/csv.h"

#include "attestation/generation/core/generator_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TDX_ATTESTATION_REPORT_DATA_SIZE 64

#ifdef __cplusplus
}
#endif

namespace kubetee {
namespace attestation {

using kubetee::UnifiedAttestationReport;

// AttestationGeneratorTdx for generating the attestation report
// for TDX TEE instance
class AttestationGeneratorTdx : public AttestationGeneratorInterface {
 public:
  TeeErrorCode Initialize(const std::string& tee_identity) override;
  TeeErrorCode CreateBgcheckReport(const UaReportGenerationParameters& param,
                                   UnifiedAttestationReport* report) override;
  TeeErrorCode CreatePassportReport(const UaReportGenerationParameters& param,
                                    UnifiedAttestationReport* report) override;

 private:
  // internal functions
  TeeErrorCode GetQuote(const UaReportGenerationParameters& param,
                        std::string* quote);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_GENERATION_PLATFORMS_CSV_UNTRUSTED_GENERATOR_TDX_H_
