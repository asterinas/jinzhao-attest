#include <string>

#include "attestation/common/attestation.h"
#include "attestation/common/log.h"
#include "attestation/common/type.h"

#ifdef __cplusplus
extern "C" {
#endif

const char kCurrentUarVersion[] = "1.0";
const char kCurrentUalVersion[] = "0.1.0";

const char kUaPlatformSgxEpid[] = "SGX_EPID";
const char kUaPlatformSgxDcap[] = "SGX_DCAP";
const char kUaPlatformHyperEnclave[] = "HyperEnclave";
const char kUaPlatformCsv[] = "CSV";
const char kUaPlatformTdx[] = "TDX";
const char kUaPlatformKunpeng[] = "Kunpeng";

const char kUaReportTypeBgcheck[] = "BackgroundCheck";
const char kUaReportTypePassport[] = "Passport";
const char kUaReportTypeUas[] = "Uas";

const char kUaAttrPlatform[] = "PLATFORM";
const char kUaAttrPlatformHwVer[] = "PLATFORMHWVERSION";
const char kUaAttrPlatformSwVer[] = "PLATFORMSWVERSION";
const char kUaAttrSecureFlags[] = "SECUREFLAGS";
const char kUaAttrMrplatform[] = "MRPLATFORM";
const char kUaAttrMrboot[] = "MRBOOT";
const char kUaAttrTeeName[] = "TEENAME";
const char kUaAttrTeeID[] = "TEEIDENTITY";
const char kUaAttrMrTa[] = "MRTRUSTAPP";
const char kUaAttrMrTaDyn[] = "MRTRUSTAPPDYN";
const char kUaAttrSigner[] = "SIGNER";
const char kUaAttrProdID[] = "PRODID";
const char kUaAttrIsvSvn[] = "ISVSVN";
const char kUaAttrDebugDisabled[] = "DEBUGDISABLED";
const char kUaAttrUserData[] = "USERDATA";
const char kUaAttrPublickey[] = "PUBLICKEY";
const char kUaAttrNonce[] = "NONCE";
const char kUaAttrSpid[] = "SPID";
const char kUaAttrVerifiedTime[] = "VERIFIEDTIME";

const char kUaNestedGroupName[] = "GROUPNAME";
const char kUaNestedGroupID[] = "GROUPID";

const int kUaReportSizeBgcheck = 8192;
const int kUaReportSizePassport = 20480;
const int kUaReportSizeUas = 8192;

// when generation ra report for occlum/VMTEE, Eid is not used
// But the interfaces need a eid, so define this dummy one
const char kDummyTeeIdentity[] = "1234";

// Empty TEE identity
const char kEmptyTeeIdentity[] = "0";

// C++ API for both trusted code nad untrusted code
//
// Nothing for C++ here, now
//

// C API for both trusted code nad untrusted code
int UnifiedAttestationReportSize(const char* report_type,
                                 unsigned int* report_size) {
  const std::string& report_type_str = SAFESTR(report_type);
  if (report_type_str == kUaReportTypeBgcheck) {
    *report_size = kUaReportSizeBgcheck;
  } else if (report_type_str == kUaReportTypePassport) {
    *report_size = kUaReportSizePassport;
  } else if (report_type_str == kUaReportTypeUas) {
    *report_size = kUaReportSizeUas;
  } else {
    TEE_LOG_ERROR("Unsupport report_type: %s", report_type);
    *report_size = 0;
    return TEE_ERROR_RA_REPORT_TYPE;
  }
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
