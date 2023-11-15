#ifndef UAL_GENERATION_PLATFORMS_HYPERENCLAVE_UNTRUSTED_GENERATOR_HYPERENCLAVE_H_
#define UAL_GENERATION_PLATFORMS_HYPERENCLAVE_UNTRUSTED_GENERATOR_HYPERENCLAVE_H_

#include <map>
#include <memory>
#include <string>

#include "./sgx_quote.h"
#include "./sgx_uae_epid.h"
#include "./sgx_uae_quote_ex.h"
#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "attestation/generation/core/generator_interface.h"

#ifdef UA_ENV_TYPE_OCCLUM  // For Occlum LibOS environment

#define SGXIOC_GET_EPID_GROUP_ID _IOR('s', 1, sgx_epid_group_id_t)
#define SGXIOC_GEN_QUOTE _IOWR('s', 2, sgxioc_gen_epid_quote_arg_t)

constexpr char kSgxDeviceName[] = "/dev/sgx";

/**
 * report_data    Input report data which will be included in quote data.
 *                The first 32 bytes should be the SHA256 hash value of
 *                the public key which is used in the RA work flow.
 * nonce          Nonce value to avoid replay attack. All zero to ignore it.
 * spid           The service provider ID, please use you real SPID,
 *                otherwise, IAS will return bad request.
 * quote_type     Maybe SGX_UNLINKABLE_SIGNATURE or SGX_LINKABLE_SIGNATURE
 *                quote type.
 * sigrl_ptr      The SigRL data buffer
 * sigrl_len      The total length of SigRL data
 * quote          Output quote structure data in binary format.
 */
typedef struct {
  sgx_report_data_t report_data;     // input
  sgx_quote_sign_type_t quote_type;  // input
  sgx_spid_t spid;                   // input
  sgx_quote_nonce_t nonce;           // input
  const uint8_t* sigrl_ptr;          // input (optional)
  uint32_t sigrl_len;                // input (optional)
  uint32_t quote_buf_len;            // input
  union {
    uint8_t* as_buf;
    sgx_quote_t* as_quote;
  } quote;  // output
} sgxioc_gen_epid_quote_arg_t;

#endif  // UA_ENV_TYPE_OCCLUM

namespace kubetee {
namespace attestation {

using kubetee::UnifiedAttestationReport;

// AttestationGeneratorHyperEnclave for generating the attestation report for
// HyperEnclave enclave instance
class AttestationGeneratorHyperEnclave : public AttestationGeneratorInterface {
 public:
  TeeErrorCode Initialize(const std::string& tee_identity) override;
  TeeErrorCode CreateBgcheckReport(const UaReportGenerationParameters& param,
                                   UnifiedAttestationReport* report) override;
  TeeErrorCode CreatePassportReport(const UaReportGenerationParameters& param,
                                    UnifiedAttestationReport* report) override;

 private:
  // internal functions
#ifdef UA_ENV_TYPE_SGXSDK
  TeeErrorCode GetSgxReport(const UaReportGenerationParameters& param,
                            sgx_report_t* p_report);
#endif
#ifdef UA_ENV_TYPE_OCCLUM
  TeeErrorCode SgxDeviceGetGroupID();
  TeeErrorCode SgxDeviceGetQuote(sgxioc_gen_epid_quote_arg_t* quote_args);
#endif
  TeeErrorCode InitTargetInfo();
  TeeErrorCode GetSgxQuote(const UaReportGenerationParameters& param,
                           std::string* pquote_b64);
  TeeErrorCode GetQuote(const UaReportGenerationParameters& param,
                        std::string* pquote_b64);

  // service provider special settings
#ifdef UA_ENV_TYPE_SGXSDK
  sgx_target_info_t target_info_;
#endif
  sgx_epid_group_id_t gid_;
  sgx_enclave_id_t enclave_id_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_GENERATION_PLATFORMS_HYPERENCLAVE_UNTRUSTED_GENERATOR_HYPERENCLAVE_H_
