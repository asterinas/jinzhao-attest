#ifndef UAL_GENERATION_PLATFORMS_CSV_UNTRUSTED_GENERATOR_CSV_H_
#define UAL_GENERATION_PLATFORMS_CSV_UNTRUSTED_GENERATOR_CSV_H_

#include <map>
#include <memory>
#include <string>

#include "attestation/platforms/csv.h"

#include "attestation/generation/core/generator_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KVM_HC_VM_ATTESTATION 100 /* Specific to HYGON CPU */
#define PAGE_MAP_FILENAME "/proc/self/pagemap"
#define PAGE_MAP_PFN_MASK 0x007fffffffffffffUL
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)  // 4096
#define PAGEMAP_LEN 8                // sizeof(uint64_t)

typedef struct {
  unsigned char data[CSV_ATTESTATION_USER_DATA_SIZE];
  unsigned char mnonce[CSV_ATTESTATION_MNONCE_SIZE];
  hash_block_t hash;
} csv_attester_user_data_t;

#ifdef __cplusplus
}
#endif

namespace kubetee {
namespace attestation {

using kubetee::UnifiedAttestationReport;

// AttestationGeneratorCsv for generating the attestation report
// for CSV VMTEE instance
class AttestationGeneratorCsv : public AttestationGeneratorInterface {
 public:
  TeeErrorCode Initialize(const std::string& tee_identity) override;
  TeeErrorCode CreateBgcheckReport(const UaReportGenerationParameters& param,
                                   UnifiedAttestationReport* report) override;
  TeeErrorCode CreatePassportReport(const UaReportGenerationParameters& param,
                                    UnifiedAttestationReport* report) override;

 private:
  // internal functions
  TeeErrorCode GetQuote(const UaReportGenerationParameters& param,
                        std::string* pquote_b64,
                        std::string* chip_id);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_GENERATION_PLATFORMS_CSV_UNTRUSTED_GENERATOR_CSV_H_
