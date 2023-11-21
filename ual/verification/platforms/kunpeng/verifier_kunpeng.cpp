#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"

#include "verification/platforms/kunpeng/kunpengsecl.h"
#include "verification/platforms/kunpeng/verifier_kunpeng.h"

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationVerifierKunpeng::Initialize(
    const kubetee::UnifiedAttestationReport& report) {
  if (!report.json_nested_reports().empty()) {
    JSON2PB(report.json_nested_reports(), &nested_reports_);
  }
  report_type_ = report.str_report_type();

  // Check the platform
  if (report.str_tee_platform() != kUaPlatformKunpeng) {
    ELOG_ERROR("It's not %s platfrom, input platform is [%s]",
               kUaPlatformKunpeng, report.str_tee_platform().c_str());
    return TEE_ERROR_RA_VERIFY_ATTR_TEE_PLATFORM;
  }

  // Get the report data, which is serialized json string of DcapReport
  kubetee::KunpengReport kunpeng_report;
  JSON2PB(report.json_report(), &kunpeng_report);
  b64_quote_body_ = kunpeng_report.b64_quote();
  quote_.SetValue(b64_quote_body_);
  TEE_CHECK_RETURN(quote_.FromBase64().GetError());

  // Parse the attester attributes from report
  TEE_CHECK_RETURN(ParseAttributes());

  // Set the platform for UnifiedAttestationAttributes
  attributes_.set_str_tee_platform(kUaPlatformKunpeng);

  // Set the hex_spid empty
  attributes_.set_hex_spid("");

  // Show the attester attributes in report
  ELOG_DEBUG("Initialize DCAP verifier successfully");
  TEE_CHECK_RETURN(ShowAttesterAttributes());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierKunpeng::VerifyPlatform(
    const kubetee::UnifiedAttestationAttributes& attr) {
  TEE_UNREFERENCED_PARAMETER(attr);
  buffer_data report;
  report.buf = quote_.data();
  report.size = quote_.size();

  // Verify the DCAP report signature and status,
  if (!kunpensecl_verify_signature(&report)) {
    ELOG_ERROR("Fail to verify the report signature");
    return TEE_ERROR_RA_VERIFY_KUNPENG_REPORT_SIGNATURE;
  }

  ELOG_DEBUG("Verify Kunpeng Platform Successfully!");
  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierKunpeng::GetReportQuote(std::string* quote) {
  quote->assign(b64_quote_body_);
  return TEE_SUCCESS;
}

/// typedef struct __attribute__((__packed__)) report_response
/// {
///     uint32_t version;
///     uint64_t ts;
///     uint8_t nonce[NONCE_SIZE];
///     TEE_UUID uuid;
///     uint32_t scenario;
///     uint32_t param_count;
///     struct ra_params params[0];
///     /* following buffer data:
///      * (1)ta_img_hash []
///      * (2)ta_mem_hash []
///      * (3)reserverd []
///      * (4)sign_ak []
///      * (5)ak_cert []
///      */
/// } kunpeng_report;
TeeErrorCode AttestationVerifierKunpeng::ParseAttributes() {
  kunpeng_report* report = RCAST(kunpeng_report*, quote_.data());
  uint32_t report_size = SCAST(uint32_t, quote_.size());
  uint8_t* start = RCAST(uint8_t*, report);

  // TODO: not suer, version for what, to be confired
  kubetee::common::DataBytes verison(report->version, sizeof(uint32_t));
  attributes_.set_hex_platform_sw_version(verison.ToHexStr().GetStr());

  kubetee::common::DataBytes nonce(report->nonce, NONCE_SIZE);
  attributes_.set_hex_nonce(nonce.ToHexStr().GetStr());

  kubetee::common::DataBytes ta_hash;
  kubetee::common::DataBytes ta_dyn_hash;
  uint32_t param_count = report->param_count;
  for (uint32_t i = 0; i < param_count; i++) {
    uint32_t param_info = report->params[i].tags;
    uint32_t param_type = (report->params[i].tags & 0xf0000000);
    if (param_type == RA_BYTES) {
      uint32_t offset = report->params[i].data.blob.data_offset;
      uint32_t len = report->params[i].data.blob.data_len;
      if (offset + len > report_size) {
        return false;
      }
      switch (param_info) {
        case RA_TAG_TA_IMG_HASH:
          ta_hash.SetValue(start + offset, SCAST(size_t, len));
          break;
        case RA_TAG_TA_MEM_HASH:
          ta_dyn_hash.SetValue(start + offset, SCAST(size_t, len));
          break;
        default:
          break;
      }
    }
  }
  attributes_.set_hex_ta_measurement(ta_hash.ToHexStr().GetStr());
  attributes_.set_hex_ta_dyn_measurement(ta_dyn_hash.ToHexStr().GetStr());

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
