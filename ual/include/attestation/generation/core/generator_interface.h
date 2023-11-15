#ifndef UAL_INCLUDE_ATTESTATION_GENERATION_CORE_GENERATOR_INTERFACE_H_
#define UAL_INCLUDE_ATTESTATION_GENERATION_CORE_GENERATOR_INTERFACE_H_

#include <string>

// We don't perfer to include any platform header files here
// For example, sgx_xxx.h
#include "attestation/common/attestation.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace attestation {

typedef struct {
  // For which TEE instance to generate the unified attestation report
  std::string tee_identity;
  // which type of unified attestation report to be generated
  std::string report_type;
  // Provide freshness if necessary.
  std::string report_hex_nonce;
  // Other generation parameters
  kubetee::UnifiedAttestationReportParams others;
} UaReportGenerationParameters;

class AttestationGeneratorInterface {
 public:
  virtual TeeErrorCode Initialize(const std::string& tee_identity) = 0;
  virtual TeeErrorCode CreatePassportReport(
      const UaReportGenerationParameters& param,
      kubetee::UnifiedAttestationReport* report) = 0;
  virtual TeeErrorCode CreateBgcheckReport(
      const UaReportGenerationParameters& param,
      kubetee::UnifiedAttestationReport* report) = 0;
  virtual ~AttestationGeneratorInterface() = default;

  TeeErrorCode PrepareReportData(const UaReportGenerationParameters& param,
                                 uint8_t* report_data_buf,
                                 size_t report_data_len);

  // Get the attester attributes
  TeeErrorCode GetAttesterAttr(kubetee::UnifiedAttestationAttributes* attr);

  // std::string tee_identity_;
  kubetee::UnifiedAttestationAttributes attributes_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_GENERATION_CORE_GENERATOR_INTERFACE_H_
