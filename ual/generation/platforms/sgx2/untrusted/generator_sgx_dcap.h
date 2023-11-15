#ifndef UAL_GENERATION_PLATFORMS_SGX2_UNTRUSTED_GENERATOR_SGX_DCAP_H_
#define UAL_GENERATION_PLATFORMS_SGX2_UNTRUSTED_GENERATOR_SGX_DCAP_H_

#include <map>
#include <memory>
#include <string>

#include "./sgx_error.h"
#include "./sgx_pce.h"
#include "./sgx_quote_3.h"
#include "./sgx_report.h"
#include "./sgx_urts.h"

#include "attestation/generation/core/generator_interface.h"

#ifdef UA_ENV_TYPE_SGXSDK
#include "./sgx_dcap_ql_wrapper.h"
#include "./sgx_dcap_qv_internal.h"
#endif

#ifdef UA_ENV_TYPE_OCCLUM
#define SGXIOC_GET_DCAP_QUOTE_SIZE _IOR('s', 7, uint32_t)
#define SGXIOC_GEN_DCAP_QUOTE _IOWR('s', 8, sgxioc_gen_dcap_quote_arg_t)

typedef struct {
  sgx_report_data_t* report_data;  // input
  uint32_t* quote_len;             // input/output
  uint8_t* quote_buf;              // output
} sgxioc_gen_dcap_quote_arg_t;
#endif

namespace kubetee {
namespace attestation {

using kubetee::UnifiedAttestationReport;

// AttestationGeneratorSgxDcap for generating the attestation report for
// SGX EPID attestation mode enclave instance
class AttestationGeneratorSgxDcap : public AttestationGeneratorInterface {
 public:
  TeeErrorCode Initialize(const std::string& eid) override;
  TeeErrorCode CreateBgcheckReport(const UaReportGenerationParameters& param,
                                   UnifiedAttestationReport* report) override;
  TeeErrorCode CreatePassportReport(const UaReportGenerationParameters& param,
                                    UnifiedAttestationReport* report) override;

 private:
  // internal functions
#ifdef UA_ENV_TYPE_SGXSDK
  TeeErrorCode LoadInProcQe();
  TeeErrorCode InitTargetInfo();
  TeeErrorCode GetSgxReport(const UaReportGenerationParameters& param);
  TeeErrorCode GetSgxQuote(std::string* quote);
#endif
  TeeErrorCode GetQuote(const UaReportGenerationParameters& param,
                        std::string* b64_quote);

#ifdef UA_ENV_TYPE_SGXSDK
  sgx_target_info_t target_info_;
  sgx_report_t report_;
#endif
  sgx_enclave_id_t enclave_id_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_GENERATION_PLATFORMS_SGX2_UNTRUSTED_GENERATOR_SGX_DCAP_H_
