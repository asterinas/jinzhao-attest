#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/scope.h"
#include "attestation/common/type.h"
#include "attestation/platforms/sgx_report_body.h"
#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace common {
namespace platforms {

// typedef struct _report_body_t {
//     sgx_cpu_svn_t        cpu_svn;      //Security Version of the CPU
//     sgx_misc_select_t    misc_select;  //Which fields defined in SSA.MISC
//     uint8_t              reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];
//     sgx_isvext_prod_id_t isv_ext_prod_id; // ISV assigned Extended Product ID
//     sgx_attributes_t     attributes;   // Special Capabilities the Enclave
//     possess sgx_measurement_t    mr_enclave;   // Enclave's Enclave
//     measurement uint8_t reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];
//     sgx_measurement_t    mr_signer;    // enclave's SIGNER measurement
//     uint8_t              reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];
//     sgx_config_id_t      config_id;    // CONFIGID
//     sgx_prod_id_t        isv_prod_id;  // Product ID of the Enclave
//     sgx_isv_svn_t        isv_svn;      // Security Version of the Enclave
//     sgx_config_svn_t     config_svn;   // CONFIGSVN
//     uint8_t              reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];
//     sgx_isvfamily_id_t   isv_family_id; // ISV assigned Family ID
//     sgx_report_data_t    report_data;   // Data provided by the user
// } sgx_report_body_t;
TeeErrorCode SgxReportBodyParser::ParseReportBody(
    sgx_report_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);
  TEE_CHECK_RETURN(ParseReportBodyMRSIGNER(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyMRENCLAVE(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyAttributes(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyIsvProd(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyIsvSvn(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyUserData(report_body, attester_attr));
  return TEE_SUCCESS;
}

TeeErrorCode SgxReportBodyParser::ParseReportBodyMRENCLAVE(
    sgx_report_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);
  kubetee::common::DataBytes mrenclave(
      RCAST(uint8_t*, &(report_body->mr_enclave)), sizeof(sgx_measurement_t));
  attester_attr->set_hex_ta_measurement(mrenclave.ToHexStr().GetStr());
  return TEE_SUCCESS;
}

TeeErrorCode SgxReportBodyParser::ParseReportBodyMRSIGNER(
    sgx_report_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);
  kubetee::common::DataBytes mrsigner(
      RCAST(uint8_t*, &(report_body->mr_signer)), sizeof(sgx_measurement_t));
  attester_attr->set_hex_signer(mrsigner.ToHexStr().GetStr());
  return TEE_SUCCESS;
}

TeeErrorCode SgxReportBodyParser::ParseReportBodyAttributes(
    sgx_report_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);
  uint64_t flags = report_body->attributes.flags;
  ELOG_DEBUG("Quote attribute flags: %lx", flags);
#ifdef DEBUGLOG
  uint64_t xfrm = report_body->attributes.xfrm;
  ELOG_DEBUG("Quote attribute xfrm: %lx", xfrm);
#endif
  if ((flags & SGX_FLAGS_DEBUG) == SGX_FLAGS_DEBUG) {
    attester_attr->set_bool_debug_disabled("false");
#if 1  // defined(EDEBUG) || defined(DEBUG)
    ELOG_WARN("The enclave is in debug mode and not trusted!");
#else
    ELOG_ERROR("The enclave is in debug mode and not trusted!");
    return TEE_ERROR_RA_VERIFY_UNEXPECTED_DEBUG_MODE;
#endif
  } else {
    attester_attr->set_bool_debug_disabled("true");
  }
  return TEE_SUCCESS;
}

TeeErrorCode SgxReportBodyParser::ParseReportBodyIsvProd(
    sgx_report_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);
  int prodid = report_body->isv_prod_id;
  attester_attr->set_hex_prod_id(std::to_string(prodid));
  return TEE_SUCCESS;
}

TeeErrorCode SgxReportBodyParser::ParseReportBodyIsvSvn(
    sgx_report_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);
  int svn = report_body->isv_svn;
  attester_attr->set_str_min_isvsvn(std::to_string(svn));
  return TEE_SUCCESS;
}

TeeErrorCode SgxReportBodyParser::ParseReportBodyUserData(
    sgx_report_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);

  // Check and parse the report data, export user data from it
  TEE_CHECK_RETURN(
      ParseReportData(report_body->report_data.d, sizeof(sgx_report_data_t),
                      attester_attr->mutable_hex_user_data(),
                      attester_attr->mutable_hex_hash_or_pem_pubkey()));

  return TEE_SUCCESS;
}

TeeErrorCode SgxReportBodyParser::ParseReportData(
    const uint8_t* report_data_buf,
    const size_t report_data_len,
    std::string* export_user_data,
    std::string* export_pubkey_hash) {
  // Check the public key hash if it exists
  if (report_data_len != (2 * kSha256Size)) {
    ELOG_ERROR("Unexpected report data size");
    return TEE_ERROR_RA_VERIFY_USER_DATA_SIZE;
  }

  // Export the lower 32 bytes as user data
  kubetee::common::DataBytes userdata(report_data_buf, kSha256Size);
  export_user_data->assign(userdata.ToHexStr().GetStr());

  // Export the higher 32 bytes as public key hash
  const uint8_t* pubkey_hash_start = report_data_buf + kSha256Size;
  kubetee::common::DataBytes pubhash(pubkey_hash_start, kSha256Size);
  export_pubkey_hash->assign(pubhash.ToHexStr().GetStr());

  return TEE_SUCCESS;
}

}  // namespace platforms
}  // namespace common
}  // namespace kubetee
