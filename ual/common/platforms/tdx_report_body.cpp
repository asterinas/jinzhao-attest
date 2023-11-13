#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "./sgx_dcap_qv_internal.h"
#include "./sgx_quote_4.h"
#include "./sgx_quote_5.h"
#include "./sgx_qve_header.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/scope.h"
#include "attestation/common/type.h"
#include "attestation/platforms/tdx_report_body.h"
#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace common {
namespace platforms {

// The TDX quote maybe in version 4 he version 5.
// But both version 4 or 5 has the same header (as far as now)
// And the sgx_report2_body_v1_5_t is compatible with sgx_report2_body_t
// Only has more fields which is not used as attestation attributes.
//
// typedef struct _sgx_report2_body_t {
//    tee_tcb_svn_t       tee_tcb_svn;          ///<  0
//    tee_measurement_t   mr_seam;              ///< 16
//    tee_measurement_t   mrsigner_seam;        ///< 64
//    tee_attributes_t    seam_attributes;      ///< 112
//    tee_attributes_t    td_attributes;        ///< 120
//    tee_attributes_t    xfam;                 ///< 128
//    tee_measurement_t   mr_td;                ///< 136
//    tee_measurement_t   mr_config_id;         ///< 184
//    tee_measurement_t   mr_owner;             ///< 232
//    tee_measurement_t   mr_owner_config;      ///< 280
//    tee_measurement_t   rt_mr[4];             ///< 328
//    tee_report_data_t   report_data;          ///< 520
//}sgx_report2_body_t;
TeeErrorCode TdxReportBodyParser::ParseReportBody(
    const std::string& quote,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  sgx_quote4_t* pquote4 = RCCAST(sgx_quote4_t*, quote.data());
  sgx_quote5_t* pquote5 = RCCAST(sgx_quote5_t*, quote.data());

  if (pquote4->header.tee_type != 0x81) {
    TEE_LOG_ERROR("Error tee_type in quote: 0x%X", pquote4->header.tee_type);
    return TEE_ERROR_RA_VERIFY_INTEL_TDX_TEE_TYPE;
  }

  int quote_version = pquote4->header.version;
  sgx_report2_body_t* report_body = nullptr;
  if (quote_version == 4) {
    report_body = &(pquote4->report_body);
  } else if (quote_version == 5) {
    TEE_LOG_DEBUG("TDX quote type: %d", pquote5->type);
    report_body = RCAST(sgx_report2_body_t*, pquote5->body);
  } else {
    TEE_LOG_ERROR("Error version in TDX quote: %d", quote_version);
    return TEE_ERROR_RA_VERIFY_INTEL_TDX_QUOTE_VERSION;
  }

  TEE_CHECK_RETURN(ParseReportBodyPfMeasurements(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyBootMeasurements(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyTaMeasurements(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyAttributes(report_body, attester_attr));
  TEE_CHECK_RETURN(ParseReportBodyUserData(report_body, attester_attr));
  return TEE_SUCCESS;
}

std::string TdxReportBodyParser::GetMrHex(const tee_measurement_t* mr) {
  kubetee::common::DataBytes mr_hex(mr->m, sizeof(tee_measurement_t));
  return mr_hex.ToHexStr().GetStr();
}

TeeErrorCode TdxReportBodyParser::ParseReportBodyPfMeasurements(
    sgx_report2_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  // All TDX platform measurements together
  std::string pms = GetMrHex(&(report_body->mr_seam));
  pms.append(GetMrHex(&(report_body->mrsigner_seam)));
  pms.append(GetMrHex(&(report_body->mr_td)));
  pms.append(GetMrHex(&(report_body->mr_config_id)));
  pms.append(GetMrHex(&(report_body->mr_owner)));
  pms.append(GetMrHex(&(report_body->mr_owner_config)));

  attester_attr->set_hex_platform_measurement(pms);
  return TEE_SUCCESS;
}

TeeErrorCode TdxReportBodyParser::ParseReportBodyBootMeasurements(
    sgx_report2_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  // All TDX boot measurements together
  std::string bms = GetMrHex(&(report_body->rt_mr[0]));
  bms.append(GetMrHex(&(report_body->rt_mr[1])));

  attester_attr->set_hex_boot_measurement(bms);
  return TEE_SUCCESS;
}

TeeErrorCode TdxReportBodyParser::ParseReportBodyTaMeasurements(
    sgx_report2_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  // All TDX TA static measurements together
  std::string tms = GetMrHex(&(report_body->rt_mr[2]));
  tms.append(GetMrHex(&(report_body->rt_mr[3])));

  attester_attr->set_hex_ta_measurement(tms);
  return TEE_SUCCESS;
}

TeeErrorCode TdxReportBodyParser::ParseReportBodyAttributes(
    sgx_report2_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);
  uint64_t attr = *(RCAST(uint64_t*, &(report_body->td_attributes)));
  ELOG_DEBUG("Quot td_attribute: %lx", attr);
#ifdef DEBUGLOG
  uint64_t xfam = *(RCAST(uint64_t*, &(report_body->xfam)));
  ELOG_DEBUG("Quote attribute xfrm: %lx", xfam);
#endif
  if ((attr & SGX_FLAGS_DEBUG) == SGX_FLAGS_DEBUG) {
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

TeeErrorCode TdxReportBodyParser::ParseReportBodyUserData(
    sgx_report2_body_t* report_body,
    kubetee::UnifiedAttestationAttributes* attester_attr) {
  TEE_CHECK_NULLPTR(report_body);

  // Check and parse the report data, export user data from it
  TEE_CHECK_RETURN(
      ParseReportData(report_body->report_data.d, sizeof(sgx_report_data_t),
                      attester_attr->mutable_hex_user_data(),
                      attester_attr->mutable_hex_hash_or_pem_pubkey()));

  return TEE_SUCCESS;
}

TeeErrorCode TdxReportBodyParser::ParseReportData(
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
